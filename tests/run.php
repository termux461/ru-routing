<?php
declare(strict_types=1);
require dirname(__DIR__) . '/src/Routing.php';

use RuRouting\Networks;
use function RuRouting\{lines, domain, cidr, build};

$checks = 0;
function check(bool $ok, string $message): void {
    global $checks;
    $checks++;
    if (!$ok) { throw new RuntimeException($message); }
}
function rejects(callable $fn): bool {
    try { $fn(); } catch (RuntimeException) { return true; }
    return false;
}
check(lines(" # comment\na.ru # inline\na.ru\n\nb.ru") === ['a.ru', 'b.ru'], 'comments/dedup');
check(domain('YANDEX.RU.') === 'yandex.ru', 'domain normalization');
foreach (['https://ya.ru', '*.ru', '127.0.0.1', 'a/b.ru', "a.ru\nother.ru"] as $bad) {
    check(rejects(fn() => domain($bad)), "invalid domain $bad");
}
foreach (['0.0.0.0/0', '10.0.0.0/8', '100.100.0.0/16', '127.0.0.1/32', '224.0.0.0/4',
    '192.0.2.0/24', '8.8.8.8/33', '8.8.8.8/-1', '8.8.8.8', '::/0'] as $bad) {
    check(rejects(fn() => cidr($bad)), "reject reserved/bad CIDR $bad");
}
check(cidr('77.88.1.99/24')[0] === '77.88.1.0/24', 'canonical CIDR');
$ru = new Networks(['77.88.0.0/18', '77.88.1.0/24', '5.255.0.0/16']);
check($ru->contains('77.88.0.0') && $ru->contains('77.88.63.255'), 'inclusive boundaries');
check($ru->contains('77.88.2.1'), 'nested ranges preserve parent coverage');
check(!$ru->contains('77.88.64.0') && !$ru->contains('1.1.1.1'), 'outside ranges');
$dns = fn($host) => match($host) {
    'ya.ru' => ['77.88.1.1', '1.1.1.1', '77.88.1.1', '10.0.0.1'],
    'bank.ru' => ['5.255.255.255', '77.88.2.1'],
    default => ['1.1.1.1'],
};
$files = build(['ya.ru', 'bank.ru', 'foreign.ru'], $ru, new Networks([]), $dns);
$amnezia = json_decode($files['tunneling-list.json'], true, 512, JSON_THROW_ON_ERROR);
check(count($amnezia) === 2, 'skip foreign-only domains');
check($amnezia[1]['ips'] === ['77.88.1.1'], 'filter CDN and private IP, deduplicate');
check(count($amnezia[0]['ips']) === 2 && $amnezia[0]['ip'] !== '', 'Amnezia legacy and multi-IP fields');
check(!str_contains($files['ru-subnets.txt'], '77.88.0.0/18'), 'no whole-country routes by default');
check(!str_contains($files['clash.yaml'], 'foreign.ru'), 'Clash excludes skipped domains');
check(json_decode($files['sing-box.json'], true)['version'] === 3, 'sing-box source format');
$all = build(['ya.ru'], $ru, new Networks(['8.8.8.8/32']), $dns, true);
check(str_contains($all['ru-subnets.txt'], '77.88.0.0/18'), 'all-RU opt in');
check(str_contains($all['ru-subnets.txt'], '8.8.8.8/32'), 'manual exceptions');
check(rejects(fn() => build(['a.ru', 'b.ru', 'ya.ru'], $ru, new Networks([]), $dns)), 'fail on widespread resolution loss');
check(rejects(fn() => build([], $ru, new Networks([]), $dns)), 'empty source rejected');
check(rejects(fn() => build(['ya.ru'], $ru, new Networks([]), function() { throw new RuntimeException('DNS timeout'); })), 'transport errors propagate');
$root = dirname(__DIR__);
$sourceDomains = lines(file_get_contents($root . '/sources/domains.txt'));
foreach ($sourceDomains as $host) {
    domain($host);
}
check(count($sourceDomains) > 0, 'real domain source is valid and nonempty');
new Networks(lines(file_get_contents($root . '/sources/cidr.txt')));
check(true, 'real CIDR source is valid');
echo "OK: $checks checks\n";
