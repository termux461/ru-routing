<?php
declare(strict_types=1);
require dirname(__DIR__) . '/src/Routing.php';
require dirname(__DIR__) . '/src/Sources.php';
require dirname(__DIR__) . '/src/Catalog.php';

use RuRouting\Networks;
use function RuRouting\{lines, domain, cidr, build, parseDns, dnsNames, asns, parsePrefixes, ipv4, checkRegression, resolveMany};

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
check(lines("# Поддомены входа/статики\r\nya.ru # Всё русское\r\nbank.ru") === ['ya.ru', 'bank.ru'], 'UTF-8 comments must not split inside multibyte characters');
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
$cut = (new Networks(['77.88.0.0/16']))->intersect(new Networks(['77.88.1.0/24', '77.88.3.0/25']));
check($cut->cidrs === ['77.88.1.0/24', '77.88.3.0/25'], 'partial RU overlap is clipped, never expanded');
check(!$cut->contains('77.88.2.1') && $cut->contains('77.88.3.127') && !$cut->contains('77.88.3.128'), 'intersection boundaries');
check(!(new Networks(['8.8.8.0/24']))->intersect($ru)->cidrs, 'disjoint networks');
check((new Networks(['77.88.0.0/25', '77.88.0.128/25']))->intersect($ru)->cidrs === ['77.88.0.0/24'], 'adjacent intervals merge');
check(dnsNames(['ya.ru', 'www.bank.ru']) === ['ya.ru' => ['ya.ru', 'www.ya.ru'], 'www.bank.ru' => ['www.bank.ru']], 'www query planning');
check(parseDns('{"Status":3}') === [], 'NXDOMAIN is a normal empty answer');
check(rejects(fn() => parseDns('{"Status":2}')), 'SERVFAIL is an error');
check(rejects(fn() => parseDns('{}')), 'missing status is an error');
check(parseDns('{"Status":0,"Answer":[{"type":5,"data":"alias.ru"},{"type":1,"data":"77.88.1.1"},{"type":1,"data":"77.88.1.1"},{"type":28,"data":"::1"}]}') === ['77.88.1.1'], 'DNS CNAME, IPv6 and duplicates');
check(asns(['as13238', 'AS13238']) === ['AS13238'], 'ASN normalization');
check(rejects(fn() => asns(['AS4294967296'])), 'ASN out of range');
check(rejects(fn() => asns(['AS1/../../'])), 'ASN injection rejected');
$ripe = '{"status":"ok","data":{"prefixes":[{"prefix":"77.88.1.0/24"},{"prefix":"2a02::/32"}]}}';
check(parsePrefixes($ripe) === ['77.88.1.0/24'], 'RIPE IPv4 only');
check(rejects(fn() => parsePrefixes('{"status":"ok","data":{"prefixes":[]}}')), 'empty ASN fails instead of dropping routes');
check(rejects(fn() => parsePrefixes('{"status":"ok","data":{"prefixes":[{"prefix":"0.0.0.0/0"}]}}')), 'RIPE default route rejected');
$protected = build(['cdn.ru'], $ru, new Networks([]), fn() => ['8.8.8.8', '1.1.1.1'], false,
    new Networks(['77.88.1.0/24']), new Networks(['8.8.8.0/24']));
check(str_contains($protected['ru-subnets.txt'], '8.8.8.8/32') && !str_contains($protected['ru-subnets.txt'], '8.8.8.0/24'), 'protection ASN adds only exact approved domain IP');
check(!str_contains($protected['ru-subnets.txt'], '1.1.1.1'), 'foreign CDN outside protection remains rejected');
check(str_contains($protected['ru-subnets.txt'], '77.88.1.0/24'), 'service prefixes are exported');
$covered = build(['ya.ru'], $ru, new Networks([]), $dns, false, new Networks(['77.88.1.0/24']));
check(!str_contains($covered['ru-subnets.txt'], '77.88.1.1/32'), 'redundant host routes removed');
check(json_decode($protected['report.json'], true)['filtered_addresses']['cdn.ru'] === ['1.1.1.1'], 'filtered addresses reported');
$emptyDns = build(['ya.ru', 'absent.ru'], $ru, new Networks([]), fn($h) => $h === 'ya.ru' ? ['77.88.1.1'] : []);
check(json_decode($emptyDns['report.json'], true)['skip_reasons']['absent.ru'] === 'no_a_record', 'skip reason reported');
foreach (['asn.txt', 'protection-asn.txt'] as $source) {
    check(count(asns(lines(file_get_contents($root . '/sources/' . $source)))) > 0, "real $source valid");
}
check(count($sourceDomains) >= 800, 'full service catalogue must not regress to a starter list');
check(!ipv4('100.100.1.1') && !ipv4('100.127.255.255') && ipv4('100.128.0.1'), 'CGNAT full range excluded');
check(rejects(fn() => checkRegression(['domains_accepted' => 800], ['domains_accepted' => 500, 'service_networks_total' => 200])), 'domain collapse aborts');
check(rejects(fn() => checkRegression(['service_networks_total' => 200], ['domains_accepted' => 800, 'service_networks_total' => 100])), 'ASN collapse aborts');
checkRegression(['domains_accepted' => 800], ['domains_accepted' => 560, 'service_networks_total' => 0]);
check(true, 'exact 30 percent boundary allowed');
$calls = 0;
$request = function($urls) use (&$calls) {
    $calls++;
    if ($calls === 1) { return [[], array_fill_keys(array_keys($urls), 'timeout')]; }
    check(str_starts_with(reset($urls), 'https://cloudflare-dns.com/'), 'fallback uses secondary DoH');
    return [array_fill_keys(array_keys($urls), '{"Status":0,"Answer":[{"type":1,"data":"77.88.1.1"}]}'), []];
};
[$result, $errors] = resolveMany(['ya.ru'], $request);
check($calls === 2 && $result['ya.ru'] === ['77.88.1.1'] && !$errors, 'fallback recovers transport errors and merges www');
$calls = 0;
resolveMany(['absent.ru'], function($urls) use (&$calls) { $calls++; return [array_fill_keys(array_keys($urls), '{"Status":3}'), []]; });
check($calls === 1, 'NXDOMAIN is not retried');
check(rejects(fn() => resolveMany(['a.ru', 'b.ru'], fn($urls) => [[], array_fill_keys(array_keys($urls), 'timeout')])), 'mass DNS failure aborts');
$categories = \RuRouting\readCategories("# 1. Banks\na.ru\n# 2. Government\nb.ru\n# Дополнения\nc.ru\n");
check($categories === ['a.ru'=>'banks','b.ru'=>'government','c.ru'=>'other'], 'categories follow sections');
check(rejects(fn() => \RuRouting\readCategories("# 1. Banks\na.ru\n# 2. Govt\na.ru\n")), 'cross-category duplicates rejected');
$sample = [['hostname'=>'a.ru','ip'=>'77.88.1.1','ips'=>['77.88.1.1']], ['hostname'=>'77.88.0.0/18','ip'=>'77.88.0.0/18','ips'=>['77.88.0.0/18']]];
$exports = \RuRouting\catalogExports($sample, ['a.ru'=>'banks'], ['built_at'=>'2026-01-01']);
check(str_contains($exports['category-banks-cidr.txt'],'77.88.1.1/32') && !str_contains($exports['category-banks-cidr.txt'],'77.88.0.0/18'), 'category excludes unrelated shared networks');
check(count(json_decode($exports['category-banks-amnezia.json'],true))===1, 'category Amnezia contains matching domain');
$diff=\RuRouting\reportChanges($sample,[['hostname'=>'a.ru','ips'=>['77.88.1.2']],['hostname'=>'b.ru','ips'=>['77.88.1.3']]]);
check($diff['added']===['b.ru'] && isset($diff['changed_ips']['a.ru']), 'changes identify new domains and changed IPs');
$upstream = "# 1. Banks\nnew-bank.ru\n# 2. Government\nnew.gov.ru\nhttps://invalid/path\n";
$found = \RuRouting\upstreamCategories($upstream);
check($found === ['new-bank.ru'=>'banks', 'new.gov.ru'=>'government'], 'upstream categories and malformed hosts');
$initial = "# 1. Banks\nold.ru\n# 2. Gov\nexisting.gov.ru\n# Дополнения\nextra.ru\n";
$merged = \RuRouting\addDiscovered($initial, $found);
$grouped = \RuRouting\readCategories($merged);
check($grouped['new-bank.ru']==='banks' && $grouped['new.gov.ru']==='government' && $grouped['old.ru']==='banks' && $grouped['extra.ru']==='other', 'automatic additions in correct category');
check(\RuRouting\addDiscovered($merged,$found)===$merged, 'automatic additions are idempotent');
check(rejects(fn()=>\RuRouting\addDiscovered($initial,['evil.ru'=>'unknown'])), 'unknown category rejected');
check(rejects(fn()=>\RuRouting\addDiscovered("# 1. Banks\nold.ru\n",['new.gov.ru'=>'government'])), 'missing target category rejected');
echo "OK: $checks checks\n";
