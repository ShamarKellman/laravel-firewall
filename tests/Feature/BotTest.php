<?php

namespace Akaunting\Firewall\Tests\Feature;

use Akaunting\Firewall\Middleware\Bot;
use Akaunting\Firewall\Tests\TestCase;
use Illuminate\Support\Facades\Config;
use Illuminate\Http\Request;
use Mockery;

class BotTest extends TestCase
{
    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    public function test_non_bot_is_not_blocked()
    {
        $parser = Mockery::mock('overload:hisorange\\BrowserDetect\\Parser');
        $parser->shouldReceive('userAgent')
            ->andReturn('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3');
        $parser->shouldReceive('isBot')
            ->andReturn(false);
        $middleware = new Bot();
        $request = Request::create('/', 'GET');
        $middleware->prepare($request);
        $this->assertFalse($middleware->check([]));
    }

    public function test_bot_is_blocked()
    {
        $parser = Mockery::mock('overload:hisorange\\BrowserDetect\\Parser');
        $parser->shouldReceive('userAgent')
            ->andReturn('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3');
        $parser->shouldReceive('isBot')
            ->andReturn(true);
        Config::set('firewall.middleware.bot.crawlers.block', ['GoogleBot']);
        $middleware = new Bot();
        $request = Request::create('/', 'GET');
        $middleware->prepare($request);
        $this->assertTrue($middleware->check([]));
    }

    public function test_bot_allowing_config_does_nothing()
    {
        $parser = Mockery::mock('overload:hisorange\\BrowserDetect\\Parser');
        $parser->shouldReceive('userAgent')
            ->andReturn('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3');
        $parser->shouldReceive('isBot')
            ->andReturn(true);
        Config::set('firewall.middleware.bot.crawlers.allow', ['OtherBot']);
        $middleware = new Bot();
        $request = Request::create('/', 'GET');
        $middleware->prepare($request);
        // Note: hisorange/browser-detect doesn't support bot names, so all bots are blocked
        $this->assertTrue($middleware->check([]));
    }
} 