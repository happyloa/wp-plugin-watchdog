<?php

use function Brain\Monkey\Functions\expect;
use function Brain\Monkey\Functions\when;
use Watchdog\Services\WPScanClient;

if (! defined('HOUR_IN_SECONDS')) {
    define('HOUR_IN_SECONDS', 3600);
}

class WPScanClientTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        when('__')->alias(static fn (string $text): string => $text);
        when('sanitize_key')->alias(static fn (string $text): string => strtolower($text));
        when('is_wp_error')->alias(static fn (mixed $response): bool => false);
        when('wp_remote_retrieve_response_code')->alias(
            static fn (array $response): int => $response['response']['code']
        );
        when('wp_remote_retrieve_body')->alias(static fn (array $response): string => $response['body']);
    }

    public function testUsesInstalledVersionAndCachesOnlyActiveVulnerabilities(): void
    {
        $slug = 'contact-form-7';
        $version = '5.8.1';
        $cacheKey = $this->cacheKey($slug, $version);

        expect('get_transient')
            ->once()
            ->with($cacheKey)
            ->andReturn(false);
        expect('get_transient')
            ->once()
            ->with('siteadwa_wpscan_error')
            ->andReturn(false);

        expect('wp_remote_get')
            ->once()
            ->withArgs(function (string $url, array $arguments): bool {
                self::assertSame(
                    'https://wpscan.com/api/v3/plugins/contact-form-7',
                    $url
                );
                self::assertSame('Token token=api-key', $arguments['headers']['Authorization']);
                self::assertSame('application/json', $arguments['headers']['Accept']);
                self::assertSame(15, $arguments['timeout']);

                return true;
            })
            ->andReturn([
                'response' => ['code' => 200],
                'body'     => json_encode([
                    $slug => [
                        'vulnerabilities' => [
                            [
                                'title'    => 'Still Active',
                                'fixed_in' => '5.8.2',
                            ],
                            [
                                'title'    => 'Fixed in Installed Version',
                                'fixed_in' => '5.8.1',
                            ],
                            [
                                'title'    => 'Historical Vulnerability',
                                'fixed_in' => '4.9.0',
                            ],
                            [
                                'title'    => 'No Known Fix',
                                'fixed_in' => null,
                                'references' => [
                                    'cve' => ['CVE-2026-0001'],
                                ],
                                'cvss' => [
                                    'score' => '9.8',
                                ],
                                'published_date' => '2026-07-01T00:00:00.000Z',
                            ],
                            'malformed-entry',
                        ],
                    ],
                ], JSON_THROW_ON_ERROR),
            ]);

        expect('delete_transient')
            ->once()
            ->with('siteadwa_wpscan_error');
        expect('set_transient')
            ->once()
            ->withArgs(function (string $key, array $value, int $ttl) use ($cacheKey): bool {
                self::assertSame($cacheKey, $key);
                self::assertSame([
                    [
                        'title'      => 'Still Active',
                        'references' => [],
                        'fixed_in'   => '5.8.2',
                        'cve'        => null,
                        'cvss_score' => null,
                        'discovered' => null,
                    ],
                    [
                        'title'      => 'No Known Fix',
                        'references' => [
                            'cve' => ['CVE-2026-0001'],
                        ],
                        'fixed_in'   => null,
                        'cve'        => 'CVE-2026-0001',
                        'cvss_score' => '9.8',
                        'discovered' => '2026-07-01T00:00:00.000Z',
                    ],
                ], $value);
                self::assertSame(12 * HOUR_IN_SECONDS, $ttl);

                return true;
            });

        $client = new WPScanClient('api-key');
        $result = $client->fetchVulnerabilities($slug, $version);

        self::assertCount(2, $result);
        self::assertSame('Still Active', $result[0]['title']);
        self::assertSame('No Known Fix', $result[1]['title']);
    }

    public function testNormalizesLeadingVWhenComparingFixedVersions(): void
    {
        $slug = 'akismet';
        $version = 'v5.3.1';
        $cacheKey = $this->cacheKey($slug, '5.3.1');

        expect('get_transient')->once()->with($cacheKey)->andReturn(false);
        expect('get_transient')->once()->with('siteadwa_wpscan_error')->andReturn(false);
        expect('wp_remote_get')
            ->once()
            ->withArgs(function (string $url): bool {
                self::assertSame('https://wpscan.com/api/v3/plugins/akismet', $url);

                return true;
            })
            ->andReturn([
                'response' => ['code' => 200],
                'body'     => json_encode([
                    'vulnerabilities' => [
                        [
                            'title'    => 'Already Fixed',
                            'fixed_in' => 'v5.3.1',
                        ],
                    ],
                ], JSON_THROW_ON_ERROR),
            ]);
        expect('delete_transient')->once()->with('siteadwa_wpscan_error');
        expect('set_transient')
            ->once()
            ->with($cacheKey, [], 12 * HOUR_IN_SECONDS);

        $client = new WPScanClient('api-key');

        self::assertSame([], $client->fetchVulnerabilities($slug, $version));
    }

    public function testSeparatesCachedResultsByInstalledVersion(): void
    {
        $slug = 'jetpack';
        $oldVersionResult = [['title' => 'Active in old version']];

        expect('get_transient')
            ->once()
            ->with($this->cacheKey($slug, '13.0'))
            ->andReturn($oldVersionResult);
        expect('get_transient')
            ->once()
            ->with($this->cacheKey($slug, '13.1'))
            ->andReturn([]);
        expect('wp_remote_get')->never();
        expect('set_transient')->never();
        expect('delete_transient')->never();

        $client = new WPScanClient('api-key');

        self::assertSame($oldVersionResult, $client->fetchVulnerabilities($slug, '13.0'));
        self::assertSame([], $client->fetchVulnerabilities($slug, '13.1'));
    }

    /**
     * @dataProvider retriableErrorResponses
     */
    public function testRetriableErrorsStartGlobalCooldown(
        int $code,
        string $expectedMessage
    ): void {
        $transients = [];
        $transientTtls = [];

        when('get_transient')->alias(
            static function (string $key) use (&$transients) {
                return $transients[$key] ?? false;
            }
        );
        when('set_transient')->alias(
            static function (string $key, mixed $value, int $ttl) use (&$transients, &$transientTtls): bool {
                $transients[$key] = $value;
                $transientTtls[$key] = $ttl;

                return true;
            }
        );

        expect('wp_remote_get')
            ->once()
            ->andReturn([
                'response' => ['code' => $code],
                'body'     => '',
            ]);
        expect('delete_transient')->never();

        $client = new WPScanClient('api-key');

        self::assertSame([], $client->fetchVulnerabilities('akismet', '5.3.1'));
        self::assertSame([], $client->fetchVulnerabilities('jetpack', '13.1'));
        self::assertSame(
            [
                'code'    => $code,
                'message' => $expectedMessage,
            ],
            $transients['siteadwa_wpscan_error']
        );
        self::assertSame(6 * HOUR_IN_SECONDS, $transientTtls['siteadwa_wpscan_error']);
    }

    public static function retriableErrorResponses(): array
    {
        return [
            'rate limit' => [
                429,
                'WPScan API rate limited; queries are paused temporarily.',
            ],
            'server error' => [
                503,
                'WPScan API is temporarily unavailable; queries are paused.',
            ],
        ];
    }

    public function testDoesNotQueryWithoutAnInstalledVersion(): void
    {
        expect('get_transient')->never();
        expect('wp_remote_get')->never();
        expect('set_transient')->never();
        expect('delete_transient')->never();

        $client = new WPScanClient('api-key');

        self::assertSame([], $client->fetchVulnerabilities('akismet'));
    }

    private function cacheKey(string $pluginSlug, string $pluginVersion): string
    {
        return 'siteadwa_wpscan_' . hash('sha256', strtolower($pluginSlug) . "\0" . $pluginVersion);
    }
}
