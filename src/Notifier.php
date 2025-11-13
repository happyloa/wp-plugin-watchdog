<?php

namespace Watchdog;

use Watchdog\Models\Risk;
use Watchdog\Repository\SettingsRepository;

class Notifier
{
    public function __construct(private readonly SettingsRepository $settingsRepository)
    {
    }

    /**
     * @param Risk[] $risks
     */
    public function notify(array $risks): void
    {
        $settings        = $this->settingsRepository->get();
        $plainTextReport = $this->formatPlainTextMessage($risks);
        $emailReport     = $this->formatEmailMessage($risks);

        if ($settings['email_enabled']) {
            $configuredRecipients = [];
            if (! empty($settings['email_recipients'])) {
                $configuredRecipients = $this->parseRecipients($settings['email_recipients']);
            }

            $recipients = $this->uniqueEmails(array_merge(
                $configuredRecipients,
                $this->getAdministratorEmails()
            ));

            if (! empty($recipients)) {
                wp_mail(
                    $recipients,
                    __('Plugin Watchdog Risk Alert', 'wp-plugin-watchdog'),
                    $emailReport,
                    ['Content-Type: text/html; charset=UTF-8']
                );
            }
        }

        if ($settings['discord_enabled'] && ! empty($settings['discord_webhook'])) {
            $this->dispatchWebhook($settings['discord_webhook'], [
                'username'  => 'WP Plugin Watchdog',
                'content'   => $plainTextReport,
            ]);
        }

        if ($settings['webhook_enabled'] && ! empty($settings['webhook_url'])) {
            $this->dispatchWebhook($settings['webhook_url'], [
                'message' => $plainTextReport,
                'risks'   => array_map(static fn (Risk $risk): array => $risk->toArray(), $risks),
            ]);
        }
    }

    private function dispatchWebhook(string $url, array $body): void
    {
        wp_remote_post($url, [
            'headers' => [
                'Content-Type' => 'application/json',
            ],
            'body'    => wp_json_encode($body),
            'timeout' => 10,
        ]);
    }

    /**
     * @param Risk[] $risks
     */
    private function formatPlainTextMessage(array $risks): string
    {
        $lines = [
            __('Potential plugin risks detected on your site:', 'wp-plugin-watchdog'),
            '',
        ];

        foreach ($risks as $risk) {
            $lines[] = sprintf(
                '%s',
                $risk->pluginName
            );
            $lines[] = sprintf(
                __('Current version: %s', 'wp-plugin-watchdog'),
                $risk->localVersion ?? __('Unknown', 'wp-plugin-watchdog')
            );
            $lines[] = sprintf(
                __('Available version: %s', 'wp-plugin-watchdog'),
                $risk->remoteVersion ?? __('N/A', 'wp-plugin-watchdog')
            );
            foreach ($risk->reasons as $reason) {
                $lines[] = sprintf('- %s', $reason);
            }
            $lines[] = '';
        }

        $lines[] = sprintf(
            __('Update plugins here: %s', 'wp-plugin-watchdog'),
            esc_url(admin_url('update-core.php'))
        );

        return implode("\n", $lines);
    }

    /**
     * @param Risk[] $risks
     */
    private function formatEmailMessage(array $risks): string
    {
        $rows = '';

        foreach ($risks as $risk) {
            $reasons = '';
            foreach ($risk->reasons as $reason) {
                $reasons .= sprintf(
                    '<li style="margin-bottom:4px;">%s</li>',
                    esc_html($reason)
                );
            }

            if (! empty($risk->details['vulnerabilities'])) {
                foreach ($risk->details['vulnerabilities'] as $vulnerability) {
                    $title = isset($vulnerability['title']) ? (string) $vulnerability['title'] : '';
                    $cve   = isset($vulnerability['cve']) ? (string) $vulnerability['cve'] : '';
                    $fixed = isset($vulnerability['fixed_in']) ? (string) $vulnerability['fixed_in'] : '';

                    $label = trim($title . ($cve !== '' ? ' - ' . $cve : ''));
                    if ($fixed !== '') {
                        $label .= ' ' . sprintf(__('(Fixed in %s)', 'wp-plugin-watchdog'), $fixed);
                    }

                    if ($label !== '') {
                        $reasons .= sprintf(
                            '<li style="margin-bottom:4px;">%s</li>',
                            esc_html($label)
                        );
                    }
                }
            }

            $rows .= sprintf(
                '<tr>
                    <td style="padding:12px 16px; border-bottom:1px solid #e6e6e6;">
                        <strong>%1$s</strong>
                        <ul style="margin:8px 0 0 18px; padding:0; list-style:disc; color:#333;">%2$s</ul>
                    </td>
                    <td style="padding:12px 16px; border-bottom:1px solid #e6e6e6; color:#333;">%3$s</td>
                    <td style="padding:12px 16px; border-bottom:1px solid #e6e6e6; color:#333;">%4$s</td>
                </tr>',
                esc_html($risk->pluginName),
                $reasons,
                esc_html($risk->localVersion ?? __('Unknown', 'wp-plugin-watchdog')),
                esc_html($risk->remoteVersion ?? __('N/A', 'wp-plugin-watchdog'))
            );
        }

        $updateUrl = esc_url(admin_url('update-core.php'));

        return sprintf(
            '<div style="font-family:-apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, sans-serif; color:#1d2327;">
                <h2 style="font-size:20px; font-weight:600;">%1$s</h2>
                <p style="font-size:14px; line-height:1.6;">%2$s</p>
                <table style="border-collapse:collapse; width:100%%; max-width:640px; background:#ffffff; border:1px solid #dcdcde;">
                    <thead>
                        <tr style="background:#f6f7f7; text-align:left; color:#1d2327;">
                            <th style="padding:12px 16px; border-bottom:1px solid #dcdcde;">%3$s</th>
                            <th style="padding:12px 16px; border-bottom:1px solid #dcdcde;">%4$s</th>
                            <th style="padding:12px 16px; border-bottom:1px solid #dcdcde;">%5$s</th>
                        </tr>
                    </thead>
                    <tbody>%6$s</tbody>
                </table>
                <p style="font-size:14px; line-height:1.6;">%7$s <a style="color:#2271b1;" href="%8$s">%8$s</a></p>
            </div>',
            esc_html(__('Plugin updates required on your site', 'wp-plugin-watchdog')),
            esc_html(__('These plugins are flagged for security or maintenance updates. Review the details below and update as soon as possible.', 'wp-plugin-watchdog')),
            esc_html(__('Plugin', 'wp-plugin-watchdog')),
            esc_html(__('Current Version', 'wp-plugin-watchdog')),
            esc_html(__('Available Version', 'wp-plugin-watchdog')),
            $rows,
            esc_html(__('Update plugins here:', 'wp-plugin-watchdog')),
            $updateUrl
        );
    }

    /**
     * @return string[]
     */
    private function parseRecipients(string $recipients): array
    {
        return array_filter(array_map('trim', explode(',', $recipients)));
    }

    /**
     * @return string[]
     */
    private function getAdministratorEmails(): array
    {
        $users = get_users([
            'role'   => 'administrator',
            'fields' => ['user_email'],
        ]);

        $emails = [];
        foreach ($users as $user) {
            if (is_object($user) && isset($user->user_email)) {
                $emails[] = trim((string) $user->user_email);
                continue;
            }

            if (is_array($user) && isset($user['user_email'])) {
                $emails[] = trim((string) $user['user_email']);
            }
        }

        return array_filter($emails);
    }

    /**
     * @param string[] $emails
     * @return string[]
     */
    private function uniqueEmails(array $emails): array
    {
        $unique = [];
        $seen   = [];

        foreach ($emails as $email) {
            $normalized = strtolower($email);
            if (isset($seen[$normalized])) {
                continue;
            }

            $seen[$normalized] = true;
            $unique[]          = $email;
        }

        return $unique;
    }
}
