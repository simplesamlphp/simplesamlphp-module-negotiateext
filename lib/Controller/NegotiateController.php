<?php

namespace SimpleSAML\Module\negotiateext\Controller;

use Exception;
use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\HTTP\RunnableResponse;
use SimpleSAML\Logger;
use SimpleSAML\Metadata\MetaDataStorageHandler;
use SimpleSAML\Module;
use SimpleSAML\Module\negotiateext\Auth\Source\Negotiate;
use SimpleSAML\Session;
use SimpleSAML\Utils;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RedirectResponse;

/**
 * Controller class for the negotiate module.
 *
 * This class serves the different views available in the module.
 *
 * @package SimpleSAML\Module\negotiate
 */
class NegotiateController
{
    /** @var \SimpleSAML\Configuration */
    protected $config;

    /** @var \SimpleSAML\Session */
    protected $session;


    /**
     * Controller constructor.
     *
     * It initializes the global configuration and session for the controllers implemented here.
     *
     * @param \SimpleSAML\Configuration              $config The configuration to use by the controllers.
     * @param \SimpleSAML\Session                    $session The session to use by the controllers.
     *
     * @throws \Exception
     */
    public function __construct(
        Configuration $config,
        Session $session
    ) {
        $this->config = $config;
        $this->session = $session;
    }


    /**
     * Perform auth.
     *
     * @return \SimpleSAML\HTTP\RunnableResponse
     */
    public function auth(): RunnableResponse
    {
        return new RunnableResponse([Negotiate::class, 'external']);
    }


    /**
     * Process authentication error
     *
     * @param Request $request The request that lead to this retry operation.
     * @return \Symfony\Component\HttpFoundation\RedirectResponse
     */
    public function error(Request $request): RedirectResponse
    {
        $query = $request->server->get('REDIRECT_QUERY_STRING');
        $url = $request->server->get('REDIRECT_URL');

        $authState = $request->get('AuthState', null);
        if ($authState === null) {
            throw new \SimpleSAML\Error\BadRequest('Missing "AuthState" parameter.');
        }

        Auth\State::loadState($authState, Negotiate::STAGEID);

        $url = str_replace('/auth', '/backend', $url . '?' . $query);
        return new RedirectResponse($url);
    }


    /**
     * Show enable.
     *
     * @return \SimpleSAML\XHTML\Template
     */
    public function enable(): Template
    {
        $this->session->setData('negotiateext:disable', 'session', false, 86400); // 24*60*60=86400

        $cookie = new \Symfony\Component\HttpFoundation\Cookie(
            'NEGOTIATE_AUTOLOGIN_DISABLE_PERMANENT',
            null, // value
            mktime(0, 0, 0, 1, 1, 2038), // expire
            '/', // path
            '', // domain
            true, // secure
            true // httponly
        );

        $t = new Template($this->config, 'negotiateext:enable.twig');
        $t->headers->setCookie($cookie);
        $t->data['url'] = Module::getModuleURL('negotiateext/disable');

        return $t;
    }


    /**
     * Show disable.
     *
     * @return \SimpleSAML\XHTML\Template
     */
    public function disable(): Template
    {
        $this->session->setData('negotiateext:disable', 'session', false, 86400); //24*60*60=86400

        $cookie = new \Symfony\Component\HttpFoundation\Cookie(
            'NEGOTIATE_AUTOLOGIN_DISABLE_PERMANENT',
            'true', // value
            mktime(0, 0, 0, 1, 1, 2038), // expire
            '/', // path
            '', // domain
            true, // secure
            true // httponly
        );

        $t = new Template($this->config, 'negotiateext:disable.twig');
        $t->headers->setCookie($cookie);
        $t->data['url'] = Module::getModuleURL('negotiateext/enable');

        return $t;
    }


    /**
     * Show retry
     *
     * @param Request $request The request that lead to this retry operation.
     * @return \SimpleSAML\HTTP\RunnableResponse
     */
    public function retry(Request $request): RunnableResponse
    {
        $authState = $request->get('AuthState', null);
        if ($authState === null) {
            throw new Error\BadRequest('Missing required AuthState query parameter.');
        }

        /** @psalm-var array $state */
        $state = Auth\State::loadState($authState, Negotiate::STAGEID);

        $metadata = MetaDataStorageHandler::getMetadataHandler();
        $idpid = $metadata->getMetaDataCurrentEntityID('saml20-idp-hosted', 'metaindex');
        $idpmeta = $metadata->getMetaData($idpid, 'saml20-idp-hosted');

        if (isset($idpmeta['auth'])) {
            $source = Auth\Source::getById($idpmeta['auth']);
            if ($source === null) {
                throw new Error\BadRequest('Invalid AuthId "' . $idpmeta['auth'] . '" - not found.');
            }

            $this->session->setData('negotiateext:disable', 'session', false, 86400); //24*60*60=86400
            Logger::debug('Negotiate(retry) - session enabled, retrying.');

            return new RunnableResponse([$source, 'authenticate'], [$state]);
        }
        throw new Exception('Negotiate - retry - no "auth" parameter found in IdP metadata.');
    }


    /**
     * Show fallback
     *
     * @param Request $request The request that lead to this retry operation.
     * @return \SimpleSAML\HTTP\RunnableResponse
     */
    public function fallback(Request $request): RunnableResponse
    {
        $authState = $request->get('AuthState', null);
        if ($authState === null) {
            throw new Error\BadRequest('Missing required AuthState query parameter.');
        }

        /** @psalm-var array $state */
        $state = Auth\State::loadState($authState, Negotiate::STAGEID);

        Logger::debug('backend - fallback: ' . $state['LogoutState']['negotiateext:backend']);

        return new RunnableResponse([Negotiate::class, 'fallback'], [$state]);
    }
}
