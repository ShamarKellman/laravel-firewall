<?php

namespace Akaunting\Firewall\Middleware;

use Akaunting\Firewall\Abstracts\Middleware;
use Akaunting\Firewall\Events\AttackDetected;
use hisorange\BrowserDetect\Facade as Browser;

class Bot extends Middleware
{
    public function check($patterns)
    {
        if (! Browser::isBot()) {
            return false;
        }

        if (! $crawlers = config('firewall.middleware.' . $this->middleware . '.crawlers')) {
            return false;
        }

        // If crawlers are configured, block all bots
        // Note: hisorange/browser-detect doesn't provide bot names,
        // so we can't filter by specific bot names like the original jenssegers/agent
        $status = true;

        if ($status) {
            $log = $this->log();

            event(new AttackDetected($log));
        }

        return $status;
    }
}
