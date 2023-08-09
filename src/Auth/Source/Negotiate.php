<?php

declare(strict_types=1);

namespace SimpleSAML\Module\negotiateext\Auth\Source;

use Exception;
use SimpleSAML\Assert\Assert;
use SimpleSAML\Auth;
use SimpleSAML\Error;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Session;
use SimpleSAML\Utils;

/**
 * The Negotiate module. Allows for password-less, secure login by Kerberos and Negotiate.
 *
 * @package simplesamlphp/simplesamlphp-module-negotiate
 */

class Negotiate extends \SimpleSAML\Auth\Source
{
    // Constants used in the module
    public const STAGEID = '\SimpleSAML\Module\negotiateext\Auth\Source\Negotiate.StageId';

    /** @var string */
    protected string $backend;

    /** @var string */
    protected string $fallback;

    /** @var string */
    protected string $keytab = '';

    /** @var array|null */
    protected ?array $subnet = null;


    /**
     * Constructor for this authentication source.
     *
     * @param array $info Information about this authentication source.
     * @param array $config The configuration of the module
     */
    public function __construct(array $info, array $config)
    {
        // call the parent constructor first, as required by the interface
        parent::__construct($info, $config);

        $cfg = \SimpleSAML\Configuration::loadFromArray($config);

        $this->backend = $cfg->getString('backend');
        $this->fallback = $cfg->getString('fallback');
        $this->subnet = $cfg->getOptionalArray('subnet', null);
    }


    /**
     * The inner workings of the module.
     *
     * Checks to see if client is in the defined subnets (if defined in config). Sends the client a 401 Negotiate and
     * responds to the result. If the client fails to provide a proper Kerberos ticket, the login process is handed over
     * to the 'fallback' module defined in the config.
     *
     * LDAP is used as a user metadata source.
     *
     * @param array &$state Information about the current authentication.
     */
    public function authenticate(array &$state): void
    {
        // set the default backend to config
        $state['LogoutState'] = [
            'negotiate:backend' => $this->backend,
        ];
        $state['negotiate:authId'] = $this->authId;
        $state['negotiate:fallback'] = $this->fallback;


        // check for disabled SPs. The disable flag is store in the SP metadata
        if (array_key_exists('SPMetadata', $state) && $this->spDisabledInMetadata($state['SPMetadata'])) {
            $this->fallBack($state);
        }
        /* Go straight to fallback if Negotiate is disabled or if you are sent back to the IdP directly from the SP
        after having logged out. */
        $session = Session::getSessionFromRequest();
        $disabled = $session->getData('negotiate:disable', 'session');

        if (
            $disabled ||
            (!empty($_REQUEST['negotiateext_auth']) &&
                $_REQUEST['negotiateext_auth'] === 'false') ||
            (!empty($_COOKIE['NEGOTIATE_AUTOLOGIN_DISABLE_PERMANENT']) &&
                $_COOKIE['NEGOTIATE_AUTOLOGIN_DISABLE_PERMANENT'] === 'true')
        ) {
            Logger::debug('Negotiate - session disabled. falling back');
            $this->fallBack($state);
            // never executed
            assert(false);
        }

        $mask = $this->checkMask();
        if (!$mask) {
            $this->fallBack($state);
            // never executed
            assert(false);
        }

        // No auth token. Send it.
        Logger::debug('Negotiate - authenticate(): Sending Negotiate.');
        // Save the $state array, so that we can restore if after a redirect
        Logger::debug('Negotiate - fallback: ' . $state['LogoutState']['negotiate:backend']);
        $id = Auth\State::saveState($state, self::STAGEID);
        $params = ['AuthState' => $id];

        $this->sendNegotiate($params);
        exit;
    }


    /**
     * @param array $spMetadata
     * @return bool
     */
    public function spDisabledInMetadata(array $spMetadata): bool
    {
        if (array_key_exists('negotiate:disable', $spMetadata)) {
            if ($spMetadata['negotiate:disable'] === true) {
                Logger::debug('Negotiate - SP disabled. falling back');
                return true;
            } else {
                Logger::debug('Negotiate - SP disable flag found but set to FALSE');
            }
        } else {
            Logger::debug('Negotiate - SP disable flag not found');
        }
        return false;
    }


    /**
     * checkMask() looks up the subnet config option and verifies
     * that the client is within that range.
     *
     * Will return TRUE if no subnet option is configured.
     *
     * @return bool
     */
    public function checkMask(): bool
    {
        // No subnet means all clients are accepted.
        if ($this->subnet === null) {
            return true;
        }
        $ip = $_SERVER['REMOTE_ADDR'];
        $netUtils = new Utils\Net();
        foreach ($this->subnet as $cidr) {
            $ret = $netUtils->ipCIDRcheck($cidr);
            if ($ret) {
                Logger::debug('Negotiate: Client "' . $ip . '" matched subnet.');
                return true;
            }
        }
        Logger::debug('Negotiate: Client "' . $ip . '" did not match subnet.');
        return false;
    }


    /**
     * Send the actual headers and body of the 401. Embedded in the body is a post that is triggered by JS if the client
     * wants to show the 401 message.
     *
     * @param array $params additional parameters to the URL in the URL in the body.
     */
    protected function sendNegotiate(array $params): void
    {
        $authPage = Module::getModuleURL('negotiateext/auth');
        $httpUtils = new Utils\HTTP();
        $httpUtils->redirectTrustedURL($authPage, $params);
    }


    /**
     * Passes control of the login process to a different module.
     *
     * @param array $state Information about the current authentication.
     *
     * @throws \SimpleSAML\Error\Error If couldn't determine the auth source.
     * @throws \SimpleSAML\Error\Exception
     * @throws \Exception
     */
    public static function fallBack(array &$state): void // never
    {
        $authId = $state['negotiate:fallback'];

        if ($authId === null) {
            throw new Error\Error([500, "Unable to determine auth source."]);
        }
        Logger::debug('Negotiate: fallBack to ' . $authId);
        $source = Auth\Source::getById($authId);

        if ($source === null) {
            throw new Exception('Could not find authentication source with id ' . $authId);
        }

        try {
            $source->authenticate($state);
        } catch (Error\Exception $e) {
            Auth\State::throwException($state, $e);
        } catch (Exception $e) {
            $e = new Error\UnserializableException($e);
            Auth\State::throwException($state, $e);
        }

        // fallBack never returns after loginCompleted()
        Logger::debug('Negotiate: backend returned');
        self::loginCompleted($state);
    }


    /**
     * @param array $state Information about the current authentication.
     */
    public function externalAuth(array &$state): void
    {
        Logger::debug('Negotiate - authenticate(): remote user found');

        $user = $_SERVER['REMOTE_USER'];
        Logger::info('Negotiate - authenticate(): ' . $user . ' authenticated.');
        $lookup = $this->lookupUserData($user);
        if ($lookup) {
            $state['Attributes'] = $lookup;
            // Override the backend so logout will know what to look for
            $state['LogoutState'] = [
                'negotiate:backend' => null,
            ];
            Logger::info('Negotiate - authenticate(): ' . $user . ' authorized.');
            Auth\Source::completeAuth($state);
            // Never reached.
            assert(false);
        }
    }


    /**
     * Passes control of the login process to a different module.
     *
     * @param string $state Information about the current authentication.
     *
     * @throws \SimpleSAML\Error\BadRequest If couldn't determine the auth source.
     * @throws \SimpleSAML\Error\NoState
     * @throws \SimpleSAML\Error\Exception
     */
    public static function external(): void
    {
        if (!isset($_REQUEST['AuthState'])) {
            throw new Error\BadRequest('Missing "AuthState" parameter.');
        }
        Logger::debug('Negotiate: external returned');
        $sid = Auth\State::parseStateID($_REQUEST['AuthState']);

        $state = Auth\State::loadState($_REQUEST['AuthState'], self::STAGEID, true);
        if ($state === null) {
            if ($sid['url'] === null) {
                throw new Error\NoState();
            }
            $httpUtils = new Utils\HTTP();
            $httpUtils->redirectUntrustedURL($sid['url'], ['negotiateext.auth' => 'false']);
            assert(false);
        }

        Assert::isArray($state);

        if (!empty($_SERVER['REMOTE_USER'])) {
            $source = Auth\Source::getById($state['negotiate:authId']);
            if ($source === null) {
                /*
                 * The only way this should fail is if we remove or rename the authentication source
                 * while the user is at the login page.
                 */
                throw new Error\Exception(
                    'Could not find authentication source with id ' . $state['negotiate:authId']
                );
            }
            /*
             * Make sure that we haven't switched the source type while the
             * user was at the authentication page. This can only happen if we
             * change config/authsources.php while an user is logging in.
             */
            if (!($source instanceof self)) {
                throw new Error\Exception('Authentication source type changed.');
            }
            Logger::debug('Negotiate - authenticate(): looking for Negotate');
            $source->externalAuth($state);
        }

        self::fallBack($state);
        assert(false);
    }


    /**
     * Strips away the realm of the Kerberos identifier, looks up what attributes to fetch from SP metadata and
     * searches the directory.
     *
     * @param string $user The Kerberos user identifier.
     *
     * @return array|null The attributes for the user or NULL if not found.
     */
    protected function lookupUserData(string $user): ?array
    {
        // Kerberos user names include realm. Strip that away.
        $pos = strpos($user, '@');
        if ($pos === false) {
            return null;
        }
        $uid = substr($user, 0, $pos);

        /** @var \SimpleSAML\Module\ldap\Auth\Source\Ldap|null $source */
        $source = Auth\Source::getById($this->backend);
        if ($source === null) {
            throw new Exception('Could not find authentication source with id ' . $this->backend);
        }

        try {
            return $source->getAttributes($uid);
        } catch (Error\Exception $e) {
            Logger::debug('Negotiate - ldap lookup failed: ' . $e);
            return null;
        }
    }


    /**
     * Log out from this authentication source.
     *
     * This method either logs the user out from Negotiate or passes the
     * logout call to the fallback module.
     *
     * @param array &$state Information about the current logout operation.
     */
    public function logout(array &$state): void
    {
        // get the source that was used to authenticate
        $authId = $state['LogoutState']['negotiate:backend'];
        Logger::debug('Negotiate - logout has the following authId: "' . $authId . '"');

        if ($authId === null) {
            $session = Session::getSessionFromRequest();
            $session->setData('negotiate:disable', 'session', true, 0);
            parent::logout($state);
        } else {
            $source = Auth\Source::getById($authId);
            if ($source === null) {
                throw new Exception('Could not find authentication source with id ' . $authId);
            }

            $source->logout($state);
        }
    }
}
