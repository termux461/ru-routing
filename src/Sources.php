<?php
declare(strict_types=1);

namespace RuRouting;

use RuntimeException;
use Throwable;

/** Bounded concurrency. Each response has its own HTTP/transport validation. */
function fetchMany(array $urls, int $concurrency = 12): array
{
    if (!extension_loaded('curl') || $concurrency < 1 || $concurrency > 32) {
        throw new RuntimeException('Нужно PHP curl; параллелизм от 1 до 32.');
    }
    $mh = curl_multi_init();
    $queue = array_keys($urls);
    $next = 0;
    $active = [];
    $bodies = $errors = [];
    try {
        do {
            while (count($active) < $concurrency && isset($queue[$next])) {
                $key = $queue[$next++];
                $ch = curl_init($urls[$key]);
                curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_CONNECTTIMEOUT => 10,
                    CURLOPT_TIMEOUT => 25, CURLOPT_FOLLOWLOCATION => false,
                    CURLOPT_PROTOCOLS => CURLPROTO_HTTPS, CURLOPT_USERAGENT => 'ru-routing-php/2.0',
                    CURLOPT_HTTPHEADER => ['Accept: application/dns-json, application/json;q=0.9']]);
                $active[spl_object_id($ch)] = [$key, $ch];
                curl_multi_add_handle($mh, $ch);
            }
            do { $status = curl_multi_exec($mh, $running); } while ($status === CURLM_CALL_MULTI_PERFORM);
            if ($status !== CURLM_OK) { throw new RuntimeException('Ошибка curl_multi.'); }
            while ($info = curl_multi_info_read($mh)) {
                $ch = $info['handle'];
                [$key] = $active[spl_object_id($ch)];
                $body = curl_multi_getcontent($ch);
                $http = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
                if ($info['result'] === CURLE_OK && $http === 200 && is_string($body) && strlen($body) <= 8_000_000) {
                    $bodies[$key] = $body;
                } else {
                    $errors[$key] = "HTTP $http; " . curl_error($ch);
                }
                curl_multi_remove_handle($mh, $ch);
                unset($active[spl_object_id($ch)]);
                curl_close($ch);
            }
            if ($active && curl_multi_select($mh, 0.25) === -1) { usleep(10000); }
        } while ($active || isset($queue[$next]));
    } finally {
        foreach ($active as [$_, $ch]) { curl_multi_remove_handle($mh, $ch); curl_close($ch); }
        curl_multi_close($mh);
    }
    return [$bodies, $errors];
}

function parseDns(string $body): array
{
    $data = json_decode($body, true, 512, JSON_THROW_ON_ERROR);
    if (!isset($data['Status']) || !in_array($data['Status'], [0, 3], true)) {
        throw new RuntimeException('DNS status ' . ($data['Status'] ?? 'missing'));
    }
    if ($data['Status'] === 3) { return []; }
    $ips = [];
    foreach ($data['Answer'] ?? [] as $answer) {
        if (($answer['type'] ?? null) === 1 && ipv4($answer['data'] ?? '')) { $ips[] = $answer['data']; }
    }
    return array_values(array_unique($ips));
}

function dnsNames(array $domains): array
{
    $names = [];
    foreach ($domains as $host) {
        $host = domain($host);
        $names[$host] = [$host];
        if (!str_starts_with($host, 'www.')) { $names[$host][] = 'www.' . $host; }
    }
    return $names;
}

function resolveMany(array $domains, ?callable $request = null): array
{
    $request ??= __NAMESPACE__ . '\\fetchMany';
    $groups = dnsNames($domains);
    $pending = [];
    foreach ($groups as $names) { foreach ($names as $host) { $pending[$host] = true; } }
    $answers = $errors = [];
    // Retry transient DNS/transport errors with an independent resolver.
    foreach (['https://dns.google/resolve?', 'https://cloudflare-dns.com/dns-query?'] as $endpoint) {
        $urls = [];
        foreach ($pending as $host => $_) { $urls[$host] = $endpoint . http_build_query(['name' => $host, 'type' => 'A']); }
        [$bodies, $transportErrors] = $request($urls);
        foreach ($pending as $host => $_) {
            try {
                if (isset($transportErrors[$host])) { throw new RuntimeException($transportErrors[$host]); }
                $answers[$host] = parseDns($bodies[$host]);
                unset($pending[$host], $errors[$host]);
            } catch (Throwable $error) { $errors[$host] = $error->getMessage(); }
        }
        if (!$pending) { break; }
    }
    if (count($errors) > max(3, (int)floor((count($answers) + count($errors)) * 0.05))) {
        throw new RuntimeException('Более 5% DNS-запросов завершились ошибкой. Сборка отменена.');
    }
    $combined = $domainErrors = [];
    foreach ($groups as $host => $names) {
        $ips = [];
        foreach ($names as $name) {
            $ips = array_merge($ips, $answers[$name] ?? []);
            if (isset($errors[$name])) { $domainErrors[$host][$name] = $errors[$name]; }
        }
        $combined[$host] = array_values(array_unique($ips));
    }
    return [$combined, $domainErrors];
}

function asns(array $values): array
{
    $out = [];
    foreach ($values as $value) {
        $value = strtoupper($value);
        if (!preg_match('/^AS([1-9][0-9]{0,9})$/D', $value, $m) || (int)$m[1] > 4294967295) {
            throw new RuntimeException("Некорректный ASN: $value");
        }
        $out[$value] = $value;
    }
    return array_values($out);
}

function parsePrefixes(string $body): array
{
    $data = json_decode($body, true, 512, JSON_THROW_ON_ERROR);
    if (($data['status'] ?? '') !== 'ok' || !isset($data['data']['prefixes']) || !is_array($data['data']['prefixes'])) {
        throw new RuntimeException('Некорректный ответ RIPEstat.');
    }
    $out = [];
    foreach ($data['data']['prefixes'] as $row) {
        $prefix = $row['prefix'] ?? '';
        if (str_contains($prefix, ':')) { continue; }
        $out[] = cidr($prefix)[0];
    }
    if (!$out) { throw new RuntimeException('RIPEstat не вернул ни одной публичной IPv4-подсети.'); }
    return array_values(array_unique($out));
}

function loadAsnNetworks(array $full, array $protection, Networks $ru): array
{
    $full = asns($full);
    $protection = asns($protection);
    if (array_intersect($full, $protection)) { throw new RuntimeException('ASN не может быть одновременно полным и точечным.'); }
    $urls = [];
    foreach (array_merge($full, $protection) as $asn) {
        $urls[$asn] = 'https://stat.ripe.net/data/announced-prefixes/data.json?' . http_build_query(['resource' => $asn]);
    }
    [$bodies, $errors] = fetchMany($urls, 6);
    $serviceNetworks = $protectionNetworks = $report = [];
    foreach ($urls as $asn => $url) {
        try {
            if (isset($errors[$asn])) { throw new RuntimeException($errors[$asn]); }
            $networks = new Networks(parsePrefixes($bodies[$asn]));
        } catch (Throwable) {
            // A single failed upstream call must not drop a company's routes silently.
            $networks = new Networks(parsePrefixes(fetch($url)));
        }
        $exactOnly = in_array($asn, $protection, true);
        $selected = $exactOnly ? $networks : $networks->intersect($ru);
        if (!$exactOnly && !$selected->cidrs) { throw new RuntimeException("У $asn нет пересечения с RU. Проверьте источник."); }
        $report[$asn] = ['mode' => $exactOnly ? 'domain-ip-only' : 'ru-service-networks',
            'announced_ipv4' => count($networks->cidrs), 'selected_ipv4' => count($selected->cidrs)];
        if ($exactOnly) { $protectionNetworks = array_merge($protectionNetworks, $selected->cidrs); }
        else { $serviceNetworks = array_merge($serviceNetworks, $selected->cidrs); }
    }
    return [new Networks($serviceNetworks), new Networks($protectionNetworks), $report];
}
