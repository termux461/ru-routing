<?php
declare(strict_types=1);
require dirname(__DIR__) . '/src/Routing.php';

use RuRouting\Networks;
use function RuRouting\{lines, domain};

$root = dirname(__DIR__);
$json = fn($name) => json_decode(file_get_contents($root . '/dist/' . $name), true, 512, JSON_THROW_ON_ERROR);
$entries = $json('tunneling-list.json');
$report = $json('report.json');
$subnets = lines(file_get_contents($root . '/dist/ru-subnets.txt'));
$coverage = new Networks($subnets);
$hosts = lines(file_get_contents($root . '/dist/domains.txt'));
$check = function(bool $ok, string $message) { if (!$ok) { throw new RuntimeException($message); } };
$check(count($entries) > 0, 'Amnezia entries empty');
$source = lines(file_get_contents($root . '/sources/domains.txt'));
foreach ($entries as $entry) {
    $check(is_string($entry['hostname']) && is_array($entry['ips']) && count($entry['ips']) > 0, 'Invalid Amnezia entry');
    $check($entry['ip'] === $entry['ips'][0], 'Legacy and current Amnezia IPs differ');
    if (str_contains($entry['hostname'], '/')) {
        $check(in_array($entry['hostname'], $subnets, true), 'Amnezia subnet missing from CIDR export');
    } else {
        domain($entry['hostname']);
        $check(in_array($entry['hostname'], $source, true), 'Unapproved domain in output');
    }
    foreach ($entry['ips'] as $ip) {
        if (!str_contains($ip, '/')) { $check($coverage->contains($ip), 'Amnezia IP missing from CIDR coverage'); }
    }
}
$check($report['domains_total'] === count($source), 'Source count mismatch');
$check($report['domains_accepted'] === count($hosts), 'Accepted domain count mismatch');
$check($report['subnets_total'] === count($subnets), 'Subnet count mismatch');
$check(count($report['skipped_domains']) + count($hosts) === count($source), 'Skipped domain count mismatch');
$sing = $json('sing-box.json');
$check($sing['version'] === 3 && $sing['rules'][0]['domain_suffix'] === $hosts, 'sing-box domain/schema mismatch');
$check($sing['rules'][0]['ip_cidr'] === $subnets, 'sing-box subnet mismatch');
$clash = file_get_contents($root . '/dist/clash.yaml');
foreach ($hosts as $host) { $check(str_contains($clash, "'DOMAIN-SUFFIX,$host'"), 'Missing Clash domain'); }
foreach ($subnets as $net) { $check(str_contains($clash, "'IP-CIDR,$net,no-resolve'"), 'Missing Clash network'); }
echo 'OK: exports agree for ' . count($hosts) . ' domains and ' . count($subnets) . " networks\n";

$catalog = $json('catalog.json');
$check(count($catalog['entries']) === count($hosts), 'Catalog domain count mismatch');
foreach ($catalog['categories'] as $category) {
    $id = $category['id'];
    $check((bool)preg_match('/^[a-z]+$/D', $id), 'Invalid category id');
    $categoryEntries = $json("category-$id-amnezia.json");
    $categorySing = $json("category-$id-sing-box.json");
    $check(count($categoryEntries) === $category['domains'], 'Category count mismatch');
    foreach ($categoryEntries as $entry) {
        $check(($catalog['domain_categories'][$entry['hostname']] ?? null) === $id, 'Wrong category');
        foreach ($entry['ips'] as $ip) $check(in_array($ip.'/32', $categorySing['rules'][0]['ip_cidr'], true), 'Missing category IP');
    }
    $check(is_file($root."/dist/category-$id-clash.yaml") && is_file($root."/dist/category-$id-cidr.txt"), 'Missing category formats');
}
echo "OK: category outputs verified\n";
