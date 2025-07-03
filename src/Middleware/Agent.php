<?php

namespace Akaunting\Firewall\Middleware;

use Akaunting\Firewall\Abstracts\Middleware;
use Akaunting\Firewall\Events\AttackDetected;
use hisorange\BrowserDetect\Facade as Browser;

class Agent extends Middleware
{
    public function check($patterns)
    {
        $status = false;

        if ($this->isMalicious()) {
            $status = true;
        }

        if (! $status && $this->isBrowser()) {
            $status = true;
        }

        if (! $status && $this->isPlatform()) {
            $status = true;
        }

        if (! $status && $this->isDevice()) {
            $status = true;
        }

        if ($status) {
            $log = $this->log();

            event(new AttackDetected($log));
        }

        return $status;
    }

    protected function isMalicious()
    {
        $agent = Browser::userAgent();

        if (empty($agent) || ($agent == '-') || strstr($agent, '<?')) {
            return true;
        }

        $patterns = [
            '@"feed_url@',
            '@}__(.*)|O:@',
            '@J?Simple(p|P)ie(Factory)?@',
        ];

        foreach ($patterns as $pattern) {
            if (! preg_match($pattern, $agent) == 1) {
                continue;
            }

            return true;
        }

        return false;
    }

    protected function isBrowser()
    {
        if (! $browsers = config('firewall.middleware.' . $this->middleware . '.browsers')) {
            return false;
        }

        $browserName = Browser::browserName();

        if (! empty($browsers['allow']) && ! in_array((string) $browserName, (array) $browsers['allow'])) {
            return true;
        }

        if (in_array((string) $browserName, (array) $browsers['block'])) {
            return true;
        }

        return false;
    }

    protected function isPlatform()
    {
        if (! $platforms = config('firewall.middleware.' . $this->middleware . '.platforms')) {
            return false;
        }

        $platformName = Browser::platformName();

        if (! empty($platforms['allow']) && ! in_array((string) $platformName, (array) $platforms['allow'])) {
            return true;
        }

        if (in_array((string) $platformName, (array) $platforms['block'])) {
            return true;
        }

        return false;
    }

    protected function isDevice()
    {
        if (! $devices = config('firewall.middleware.' . $this->middleware . '.devices')) {
            return false;
        }

        $list = ['Desktop', 'Mobile', 'Tablet'];

        foreach ((array) $devices['allow'] as $allow) {
            if (! in_array($allow, $list)) {
                continue;
            }

            $function = 'is' . ucfirst($allow);

            if (method_exists(Browser::class, $function) && Browser::$function()) {
                continue;
            }

            return true;
        }

        foreach ((array) $devices['block'] as $block) {
            if (! in_array($block, $list)) {
                continue;
            }

            $function = 'is' . ucfirst($block);

            if (method_exists(Browser::class, $function) && !Browser::$function()) {
                continue;
            }

            return true;
        }

        return false;
    }
}
