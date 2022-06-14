<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\negotiateext\Controller;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\HTTP\RunnableResponse;
use SimpleSAML\Module\negotiateext\Controller;
use SimpleSAML\Session;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RedirectResponse;

/**
 * Set of tests for the controllers in the "negotiate" module.
 *
 * @package SimpleSAML\Test
 */
class NegotiateTest extends TestCase
{
    /** @var \SimpleSAML\Configuration */
    protected Configuration $config;

    /** @var \SimpleSAML\Session */
    protected Session $session;

    /**
     * Set up for each test.
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->config = Configuration::loadFromArray(
            [
                'module.enable' => ['negotiateext' => true],
            ],
            '[ARRAY]',
            'simplesaml'
        );

        $this->session = Session::getSessionFromRequest();

        Configuration::setPreLoadedConfig($this->config, 'config.php');
    }


    /**
     * Test that a valid requests results in a RunnableResponse
     */
    public function testAuth(): void
    {
        $request = Request::create(
            '/auth',
            'GET'
        );

        $c = new Controller\NegotiateController($this->config, $this->session);

        $response = $c->auth($request);

        $this->assertInstanceOf(RunnableResponse::class, $response);
        $this->assertTrue($response->isSuccessful());
    }


    /**
     * Test that a valid requests results in a RedirectResponse
    public function testError(): void
    {
        $request = Request::create(
            '/error',
            'GET'
        );

        $c = new Controller\NegotiateController($this->config, $this->session);

        $response = $c->error($request);

        $this->assertInstanceOf(RedirectResponse::class, $response);
        $this->assertTrue($response->isSuccessful());
    }
     */


    /**
     * Test that a missing AuthState results in a BadRequest-error
     */
    public function testErrorMissingState(): void
    {
        $request = Request::create(
            '/error',
            'GET'
        );

        $c = new Controller\NegotiateController($this->config, $this->session);

        $this->expectException(Error\BadRequest::class);
        $this->expectExceptionMessage('BADREQUEST(\'%REASON%\' => \'Missing "AuthState" parameter.\')');

        $c->error($request);
    }


    /**
     * Test that an invalid AuthState results in a NOSTATE-error
     */
    public function testErrorInvalidState(): void
    {
        $request = Request::create(
            '/error',
            'GET',
            ['AuthState' => 'someState']
        );

        $c = new Controller\NegotiateController($this->config, $this->session);

        $this->expectException(Error\NoState::class);
        $this->expectExceptionMessage('NOSTATE');

        $c->error($request);
    }


    /**
     * Test that a valid requests results in a Twig template
     */
    public function testEnable(): void
    {
        $request = Request::create(
            '/enable',
            'GET'
        );

        $c = new Controller\NegotiateController($this->config, $this->session);

        /** @var \SimpleSAML\XHTML\Template $response */
        $response = $c->enable($request);

        // Validate response
        $this->assertInstanceOf(Template::class, $response);
        $this->assertTrue($response->isSuccessful());

        // Validate cookie
        $cookies = $response->headers->getCookies();
        foreach ($cookies as $cookie) {
            if ($cookie->getName() === 'NEGOTIATE_AUTOLOGIN_DISABLE_PERMANENT') {
                break;
            }
        }

        $this->assertEquals($cookie->getValue(), null);
        $this->assertEquals($cookie->getDomain(), null);
        $this->assertEquals($cookie->getPath(), '/');
        $this->assertEquals($expiration = $cookie->getExpiresTime(), mktime(0, 0, 0, 1, 1, 2038));
        $this->assertEquals($cookie->getMaxAge(), $expiration - time());
        $this->assertTrue($cookie->isSecure());
        $this->assertTrue($cookie->isHttpOnly());
    }


    /**
     * Test that a valid requests results in a Twig template
     */
    public function testDisable(): void
    {
        $request = Request::create(
            '/disable',
            'GET'
        );

        $c = new Controller\NegotiateController($this->config, $this->session);

        /** @var \SimpleSAML\XHTML\Template $response */
        $response = $c->disable($request);

        // Validate response
        $this->assertInstanceOf(Template::class, $response);
        $this->assertTrue($response->isSuccessful());

        // Validate cookie
        $cookies = $response->headers->getCookies();
        foreach ($cookies as $cookie) {
            if ($cookie->getName() === 'NEGOTIATE_AUTOLOGIN_DISABLE_PERMANENT') {
                break;
            }
        }

        $this->assertEquals($cookie->getValue(), 'true');
        $this->assertEquals($cookie->getDomain(), null);
        $this->assertEquals($cookie->getPath(), '/');
        $this->assertEquals($expiration = $cookie->getExpiresTime(), mktime(0, 0, 0, 1, 1, 2038));
        $this->assertEquals($cookie->getMaxAge(), $expiration - time());
        $this->assertTrue($cookie->isSecure());
        $this->assertTrue($cookie->isHttpOnly());
    }


    /**
     * Test that a valid requests results in a RunnableResponse
    public function testRetry(): void
    {
        $request = Request::create(
            '/retry',
            'GET',
            ['AuthState' => 'someState'],
        );

        $c = new Controller\NegotiateController($this->config, $this->session);

        $response = $c->retry($request);

        $this->assertInstanceOf(RunnableResponse::class, $response);
        $this->assertTrue($response->isSuccessful());
    }
     */



    /**
     * Test that a missing AuthState results in a BadRequest-error
     */
    public function testRetryMissingState(): void
    {
        $request = Request::create(
            '/retry',
            'GET'
        );

        $c = new Controller\NegotiateController($this->config, $this->session);

        $this->expectException(Error\BadRequest::class);
        $this->expectExceptionMessage('BADREQUEST(\'%REASON%\' => \'Missing required AuthState query parameter.\')');

        $c->retry($request);
    }


    /**
     * Test that an invalid AuthState results in a NOSTATE-error
     */
    public function testRetryInvalidState(): void
    {
        $request = Request::create(
            '/retry',
            'GET',
            ['AuthState' => 'someState']
        );

        $c = new Controller\NegotiateController($this->config, $this->session);

        $this->expectException(Error\NoState::class);
        $this->expectExceptionMessage('NOSTATE');

        $c->retry($request);
    }


    /**
     * Test that a valid requests results in a RunnableResponse
    public function testBackend(): void
    {
        $request = Request::create(
            '/backend',
            'GET',
            ['AuthState' => 'someState'],
        );

        $c = new Controller\NegotiateController($this->config, $this->session);

        $response = $c->fallback($request);

        $this->assertInstanceOf(RunnableResponse::class, $response);
        $this->assertTrue($response->isSuccessful());
    }
     */


    /**
     * Test that a missing AuthState results in a BadRequest-error
     */
    public function testBackendMissingState(): void
    {
        $request = Request::create(
            '/backend',
            'GET'
        );

        $c = new Controller\NegotiateController($this->config, $this->session);

        $this->expectException(Error\BadRequest::class);
        $this->expectExceptionMessage('BADREQUEST(\'%REASON%\' => \'Missing required AuthState query parameter.\')');

        $c->fallback($request);
    }


    /**
     * Test that an invalid AuthState results in a NOSTATE-error
     */
    public function testBackendInvalidState(): void
    {
        $request = Request::create(
            '/backend',
            'GET',
            ['AuthState' => 'someState']
        );

        $c = new Controller\NegotiateController($this->config, $this->session);

        $this->expectException(Error\NoState::class);
        $this->expectExceptionMessage('NOSTATE');

        $c->fallback($request);
    }
}
