<?php

/**
 * Provide a URL for the module to statically link to.
 *
 * @author Mathias Meisfjordskar, University of Oslo.
 *         <mathias.meisfjordskar@usit.uio.no>
 * @package SimpleSAMLphp
 */

if (!isset($_REQUEST['AuthState'])) {
    throw new \SimpleSAML\Error\BadRequest('Missing "AuthState" parameter.');
}

/** @var array $state */
$state = \SimpleSAML\Auth\State::loadState(
    $_REQUEST['AuthState'],
    \SimpleSAML\Module\negotiateext\Auth\Source\Negotiate::STAGEID
);

\SimpleSAML\Logger::debug('backend - fallback: ' . $state['LogoutState']['negotiate:backend']);

\SimpleSAML\Module\negotiateext\Auth\Source\Negotiate::fallBack($state);

exit;
