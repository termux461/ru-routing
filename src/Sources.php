<?php
declare(strict_types=1);

namespace RuRouting;

use RuntimeException;
use Throwable;

/** Bounded concurrency. Each response has its own HTTP/transport validation. */
function fetchMany(array $urls, int $concurrency = 12, string $accept = 'application/dns-json, application/json;q=0.9'): array
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
                    CURLOPT_HTTPHEADER => ['Accept: ' . $accept]]);
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

/** RFC 8484 GET query, encoded without a transport-specific DNS library. */
function dnsWireQuery(string $host): string {
    $host=domain($host); $q=''; foreach(explode('.', $host) as $part) { if(strlen($part)>63) throw new RuntimeException('DNS label too long'); $q.=chr(strlen($part)).$part; }
    return pack('nnnnnn',0,0x0100,1,0,0,0).$q."\0".pack('nn',1,1);
}
function skipWireName(string $body,int &$offset): void {
    $size=strlen($body); $labels=0;
    while(true) {
        if($offset >= $size || ++$labels>128) throw new RuntimeException('Некорректное DNS-имя');
        $n=ord($body[$offset++]);
        if($n===0) return;
        if(($n & 0xc0)===0xc0) { if($offset >= $size || ((($n & 0x3f)<<8)|ord($body[$offset])) >= $size) throw new RuntimeException('Некорректный DNS-указатель'); $offset++; return; }
        if(($n & 0xc0)!==0 || $n>63 || $offset+$n>$size) throw new RuntimeException('Некорректная DNS-метка');
        $offset+=$n;
    }
}
function parseWireDns(string $body, string $host): array {
    if(strlen($body)<12 || strlen($body)>65535) throw new RuntimeException('Некорректный DNS-ответ');
    $h=unpack('nid/nflags/nqd/nan/nns/nar',substr($body,0,12));
    if($h['id']!==0 || !($h['flags'] & 0x8000) || ($h['flags'] & 0x0200) || $h['qd']!==1 || $h['an']>1000) throw new RuntimeException('Некорректный DNS-заголовок');
    $rcode=$h['flags'] & 15; if($rcode!==0 && $rcode!==3) throw new RuntimeException('DNS status '.$rcode);
    $q=dnsWireQuery($host); $question=substr($q,12);
    if(substr($body,12,strlen($question))!==$question) throw new RuntimeException('DNS question mismatch');
    $offset=12+strlen($question); $ips=[];
    for($i=0;$i<$h['an'];$i++) {
        skipWireName($body,$offset); if($offset+10>strlen($body)) throw new RuntimeException('Обрезанный DNS-ответ');
        $row=unpack('ntype/nclass/Nttl/nlen',substr($body,$offset,10));$offset+=10;
        if($offset+$row['len']>strlen($body)) throw new RuntimeException('Обрезанный DNS-адрес');
        if($row['type']===1 && $row['class']===1 && $row['len']===4) { $ip=inet_ntop(substr($body,$offset,4)); if($ip!==false && ipv4($ip)) $ips[]=$ip; }
        $offset+=$row['len'];
    }
    return array_values(array_unique($ips));
}
function resolveMany(array $domains, ?callable $request = null): array {
    $request ??= __NAMESPACE__ . '\\fetchMany';
    $groups=dnsNames($domains); $pending=[];
    foreach($groups as $names) foreach($names as $host) $pending[$host]=true;
    $answers=$errors=$successful=[];
    $providers=[['https://dns.google/resolve?',false],['https://cloudflare-dns.com/dns-query?',true],['https://dns.adguard-dns.com/dns-query?',true]];
    foreach($providers as [$endpoint,$wire]) {
        $urls=[];foreach($pending as $host=>$_) {
            $urls[$host]=$endpoint.($wire ? 'dns='.rtrim(strtr(base64_encode(dnsWireQuery($host)),'+/','-_'),'=') : http_build_query(['name'=>$host,'type'=>'A']));
        }
        if(!$urls) break;
        [$bodies,$transportErrors]=$wire ? $request($urls,12,'application/dns-message') : $request($urls);
        foreach($pending as $host=>$_) {
            try {
                if(isset($transportErrors[$host])) throw new RuntimeException($transportErrors[$host]);
                $ips=$wire ? parseWireDns($bodies[$host],$host) : parseDns($bodies[$host]);
                $successful[$host]=true; $answers[$host]=$ips; unset($errors[$host]);
                if($ips) unset($pending[$host]);
            } catch(Throwable $e) { if(!isset($successful[$host])) $errors[$host]=$e->getMessage(); }
        }
    }
    if(count($errors)>max(3,(int)floor((count($answers)+count($errors))*0.05))) throw new RuntimeException('Более 5% DNS-запросов завершились ошибкой. Сборка отменена.');
    $combined=$domainErrors=[];
    foreach($groups as $host=>$names) {
        $ips=[];foreach($names as $name) { $ips=array_merge($ips,$answers[$name]??[]); if(isset($errors[$name])) $domainErrors[$host][$name]=$errors[$name]; }
        $combined[$host]=array_values(array_unique($ips));
    }
    return [$combined,$domainErrors];
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
