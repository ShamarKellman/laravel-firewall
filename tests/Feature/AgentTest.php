<?php

namespace Akaunting\Firewall\Tests\Feature;

use Akaunting\Firewall\Middleware\Agent;
use Akaunting\Firewall\Tests\TestCase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Mockery;

class AgentTest extends TestCase
{
    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    public function test_malicious_user_agent_is_blocked()
    {
        Mockery::mock('overload:hisorange\\BrowserDetect\\Parser')
            ->shouldReceive('userAgent')
            ->andReturn('<?php evil');
        $middleware = new Agent();

        $request = Request::create('/', 'GET');
        $middleware->prepare($request);

        $this->assertTrue($middleware->check([]));
    }

    public function test_browser_blocking()
    {
        Config::set('firewall.middleware.agent.browsers.block', ['Chrome']);
        $parser = Mockery::mock('overload:hisorange\\BrowserDetect\\Parser');
        $parser->shouldReceive('userAgent')
            ->andReturn('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3');
        $parser->shouldReceive('browserName')
            ->andReturn('Chrome');
        $middleware = new Agent();
        $request = Request::create('/', 'GET');
        $middleware->prepare($request);
        $this->assertTrue($middleware->check([]));
    }

    public function test_browser_allowing()
    {
        Config::set('firewall.middleware.agent.browsers.allow', ['Firefox']);
        $parser = Mockery::mock('overload:hisorange\\BrowserDetect\\Parser');
        $parser->shouldReceive('userAgent')
            ->andReturn('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3');
        $parser->shouldReceive('browserName')
            ->andReturn('Chrome');
        $middleware = new Agent();
        $request = Request::create('/', 'GET');
        $middleware->prepare($request);
        $this->assertTrue($middleware->check([]));
    }

    public function test_platform_blocking()
    {
        Config::set('firewall.middleware.agent.platforms.block', ['Windows']);
        $parser = Mockery::mock('overload:hisorange\\BrowserDetect\\Parser');
        $parser->shouldReceive('userAgent')
            ->andReturn('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3');
        $parser->shouldReceive('platformName')
            ->andReturn('Windows');
        $parser->shouldReceive('browserName')
            ->andReturn('Chrome');
        $middleware = new Agent();
        $request = Request::create('/', 'GET');
        $middleware->prepare($request);
        $this->assertTrue($middleware->check([]));
    }

    public function test_device_blocking()
    {
        Config::set('firewall.middleware.agent.devices.block', ['Desktop']);
        $parser = Mockery::mock('overload:hisorange\\BrowserDetect\\Parser');
        $parser->shouldReceive('userAgent')
            ->andReturn('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3');
        $parser->shouldReceive('isDesktop')
            ->andReturn(true);
        $parser->shouldReceive('browserName')
            ->andReturn('Chrome');
        $parser->shouldReceive('platformName')
            ->andReturn('Windows');
        $middleware = new Agent();
        $request = Request::create('/', 'GET');
        $middleware->prepare($request);
        $this->assertTrue($middleware->check([]));
    }
}
