<?php
declare(strict_types=1);

namespace RuRouting;

use RuntimeException;

function lines(string $text): array
{
    $result = [];
    foreach (preg_split('/\R/', $text) as $line) {
        $line = trim(explode('#', $line, 2)[0]);
        if ($line !== '') {
            $result[$line] = true;
        }
    }
    return array_keys($result);
}

function domain(string $value): string
{
    $value = strtolower(rtrim(trim($value), '.'));
    if (!str_contains($value, '.') || filter_var($value, FILTER_VALIDATE_IP)
        || !filter_var($value, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
        throw new RuntimeException("Некорректный домен: $value. Для кириллицы используйте punycode.");
    }
    return $value;
}

function ipv4(string $ip): bool
{
    return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false
        && (int)explode('.', $ip)[0] > 0 && (int)explode('.', $ip)[0] < 224
        && !str_starts_with($ip, '100.64.') && !str_starts_with($ip, '169.254.');
}

/** Return the canonical network and its inclusive integer bounds (64-bit PHP). */
function cidr(string $value): array
{
    if (!preg_match('~^([^/]+)/(\d{1,2})$~D', $value, $m)
        || !filter_var($m[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)
        || (int)$m[2] < 1 || (int)$m[2] > 32) {
        throw new RuntimeException("Некорректная IPv4-подсеть: $value");
    }
    $prefix = (int)$m[2];
    $size = 1 << (32 - $prefix);
    $start = intdiv(ip2long($m[1]), $size) * $size;
    $end = $start + $size - 1;
    // Never allow a manual rule to swallow special-use networks.
    foreach (['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
        '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.168.0.0/16', '198.18.0.0/15',
        '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/3'] as $reserved) {
        [$ip, $bits] = explode('/', $reserved);
        $low = ip2long($ip);
        $high = $low + (1 << (32 - (int)$bits)) - 1;
        if ($start <= $high && $end >= $low) {
            throw new RuntimeException("Подсеть пересекается со служебной: $value");
        }
    }
    return [long2ip($start) . '/' . $prefix, $start, $end];
}

final class Networks
{
    private array $ranges = [];
    public array $cidrs = [];

    public function __construct(array $values)
    {
        foreach ($values as $value) {
            [$canonical, $start, $end] = cidr($value);
            $this->cidrs[$canonical] = $canonical;
            $this->ranges[] = [$start, $end];
        }
        $this->cidrs = array_values($this->cidrs);
        sort($this->cidrs, SORT_STRING);
        usort($this->ranges, fn($a, $b) => $a[0] <=> $b[0]);
        $merged = [];
        foreach ($this->ranges as [$start, $end]) {
            $i = count($merged) - 1;
            if ($i >= 0 && $start <= $merged[$i][1] + 1) {
                $merged[$i][1] = max($merged[$i][1], $end);
            } else {
                $merged[] = [$start, $end];
            }
        }
        $this->ranges = $merged;
    }

    public function contains(string $ip): bool
    {
        if (!ipv4($ip)) {
            return false;
        }
        $n = ip2long($ip);
        $low = 0;
        $high = count($this->ranges) - 1;
        while ($low <= $high) {
            $mid = intdiv($low + $high, 2);
            [$start, $end] = $this->ranges[$mid];
            if ($n < $start) {
                $high = $mid - 1;
            } elseif ($n > $end) {
                $low = $mid + 1;
            } else {
                return true;
            }
        }
        return false;
    }
}

function fetch(string $url): string
{
    if (!extension_loaded('curl')) {
        throw new RuntimeException('Нужно расширение PHP curl.');
    }
    $last = '';
    for ($attempt = 0; $attempt < 3; $attempt++) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_TIMEOUT => 25, CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS, CURLOPT_USERAGENT => 'ru-routing-php/1.0',
            CURLOPT_HTTPHEADER => ['Accept: application/dns-json, text/plain;q=0.9']]);
        $body = curl_exec($ch);
        $status = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $last = curl_error($ch);
        curl_close($ch);
        if (is_string($body) && $status === 200 && strlen($body) <= 8_000_000) {
            return $body;
        }
        $last = "HTTP $status: $last";
        if ($attempt < 2) {
            usleep(300000);
        }
    }
    throw new RuntimeException("Не удалось скачать $url ($last)");
}

function resolve(string $host): array
{
    $data = json_decode(fetch('https://dns.google/resolve?' . http_build_query(['name' => $host, 'type' => 'A'])), true, 512, JSON_THROW_ON_ERROR);
    if (!isset($data['Status']) || !in_array($data['Status'], [0, 3], true)) {
        throw new RuntimeException("Ошибка DNS для $host");
    }
    $ips = [];
    foreach ($data['Answer'] ?? [] as $answer) {
        if (($answer['type'] ?? null) === 1 && ipv4($answer['data'] ?? '')) {
            $ips[] = $answer['data'];
        }
    }
    return array_values(array_unique($ips));
}

/** DNS is injectable so regression tests never depend on the network. */
function build(array $domains, Networks $ru, Networks $manual, callable $resolver, bool $allRu = false): array
{
    $hosts = array_unique(array_map(__NAMESPACE__ . '\\domain', $domains));
    sort($hosts, SORT_STRING);
    if (!$hosts) {
        throw new RuntimeException('Список доменов пуст.');
    }
    $entries = [];
    $accepted = [];
    $skipped = [];
    $ipSet = [];
    foreach ($hosts as $host) {
        $addresses = $resolver($host);
        $ips = array_values(array_unique(array_filter($addresses, fn($ip) => $ru->contains($ip) || $manual->contains($ip))));
        sort($ips, SORT_STRING);
        if (!$ips) {
            $skipped[] = $host;
            continue;
        }
        $accepted[] = $host;
        $entries[] = ['hostname' => $host, 'ip' => $ips[0], 'ips' => $ips];
        foreach ($ips as $ip) {
            $ipSet[$ip . '/32'] = true;
        }
    }
    // A broken DNS/feed must not silently replace working lists with nearly empty output.
    if (count($accepted) < max(1, (int)ceil(count($hosts) / 2))) {
        throw new RuntimeException('Менее половины доменов получили разрешённые IP. Предыдущая сборка сохранена. Проверьте DNS и RU-список.');
    }
    $subnets = array_values(array_unique(array_merge(array_keys($ipSet), $manual->cidrs, $allRu ? $ru->cidrs : [])));
    sort($subnets, SORT_STRING);
    foreach (array_values(array_unique(array_merge($manual->cidrs, $allRu ? $ru->cidrs : []))) as $network) {
        $entries[] = ['hostname' => $network, 'ip' => $network, 'ips' => [$network]];
    }
    $json = fn($v) => json_encode($v, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n";
    $clash = "payload:\n";
    foreach ($accepted as $host) {
        $clash .= "  - 'DOMAIN-SUFFIX,$host'\n";
    }
    foreach ($subnets as $net) {
        $clash .= "  - 'IP-CIDR,$net,no-resolve'\n";
    }
    return [
        'tunneling-list.json' => $json($entries),
        'ru-subnets.txt' => implode("\n", $subnets) . "\n",
        'domains.txt' => implode("\n", $accepted) . "\n",
        'sing-box.json' => $json(['version' => 3, 'rules' => [['domain_suffix' => $accepted, 'ip_cidr' => $subnets]]]),
        'clash.yaml' => $clash,
        'report.json' => $json(['built_at' => gmdate('c'), 'mode' => $allRu ? 'all-ru' : 'services',
            'domains_total' => count($hosts), 'domains_accepted' => count($accepted),
            'subnets_total' => count($subnets), 'skipped_domains' => $skipped,
            'note' => 'RU registration is not proof of hosting location or exclusive ownership; shared IPs can bypass unrelated sites.']),
    ];
}
