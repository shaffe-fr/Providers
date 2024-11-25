<?php

namespace SocialiteProviders\FranceConnect;

use Firebase\JWT\JWT;
use GuzzleHttp\RequestOptions;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use Laravel\Socialite\Two\InvalidStateException;
use SocialiteProviders\Manager\OAuth2\AbstractProvider;
use SocialiteProviders\Manager\OAuth2\User;

class Provider extends AbstractProvider
{
    /**
     * Provider identifier.
     */
    public const IDENTIFIER = 'FRANCECONNECT';

    /**
     * Base URLs for production and integration.
     */
    private const URLS = [
        'production' => 'https://oidc.franceconnect.gouv.fr/api/v2',
        'integration' => 'https://fcp-low.integ01.dev-franceconnect.fr/api/v2',
    ];

    /**
     * {@inheritdoc}
     */
    protected $scopes = [
        'openid',
        'profile',
        'email',
    ];

    /**
     * {@inheritdoc}
     */
    protected $scopeSeparator = ' ';

    /**
     * Override to allow custom config keys.
     */
    public static function additionalConfigKeys(): array
    {
        return ['logout_redirect', 'environment', 'acr_values', 'prompt'];
    }

    /**
     * {@inheritdoc}
     */
    protected function getAuthUrl($state): string
    {
        // generate and store nonce to validate ID token
        $nonce = Str::random(22);
        $this->request->session()->put('fc_nonce', $nonce);

        return $this->buildAuthUrlFromBase(
            $this->getBaseUrl() . '/authorize',
            $state
        );
    }

    /**
     * {@inheritdoc}
     */
    protected function getCodeFields($state = null): array
    {
        $fields = parent::getCodeFields($state);

        // custom acr and prompt or default
        $fields['acr_values'] = $this->getConfig('acr_values') ?: 'eidas1';
        $fields['prompt'] = $this->getConfig('prompt') ?: 'consent';

        // include nonce for OIDC
        $fields['nonce'] = $this->request->session()->get('fc_nonce');

        return $fields;
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenUrl(): string
    {
        return $this->getBaseUrl() . '/token';
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessTokenResponse($code)
    {
        // Use Basic auth header and minimal body
        $response = $this->getHttpClient()->post($this->getTokenUrl(), [
            RequestOptions::HEADERS => ['Accept' => 'application/json'],
            RequestOptions::FORM_PARAMS => $this->getTokenFields($code),
        ]);

        return json_decode((string) $response->getBody(), true);
    }

    /**
     * {@inheritdoc}
     */
    public function user(): User
    {
        if ($this->hasInvalidState()) {
            throw new InvalidStateException;
        }

        $response = $this->getAccessTokenResponse($this->getCode());
        $accessToken = Arr::get($response, 'access_token');

        // optionally merge with userinfo
        $userData = $this->getUserByToken($accessToken);

        /** @var \SocialiteProviders\Manager\OAuth2\User $user */
        $user = $this->mapUserToObject($userData);

        return $user
            ->setAccessTokenResponseBody($response)
            ->setToken($accessToken)
            ->setRefreshToken(Arr::get($response, 'id_token'))
            ->setExpiresIn(Arr::get($response, 'expires_in'))
            ->setApprovedScopes(explode($this->scopeSeparator, $response['scope']));
    }

    /**
     * {@inheritdoc}
     */
    protected function getUserByToken($token): array
    {
        $response = $this->getHttpClient()->get($this->getBaseUrl() . '/userinfo', [
            RequestOptions::HEADERS => [
                'Authorization' => 'Bearer ' . $token,
                'Accept'        => 'application/jwt',
            ],
        ]);

        $jwt = (string) $response->getBody();
        $parts = explode('.', $jwt);

        if (count($parts) < 2) {
            throw new \RuntimeException('JWT invalide reçu de FranceConnect userinfo');
        }

        $payloadSegment = $parts[1];
        $decodedJson    = JWT::jsonDecode(JWT::urlsafeB64Decode($payloadSegment));

        return is_object($decodedJson) ? (array) $decodedJson : [];
    }

    /**
     * {@inheritdoc}
     */
    protected function mapUserToObject(array $user): User
    {
        return (new User())->setRaw($user)->map([
            'id' => Arr::get($user, 'sub'),
            'nickname' => Arr::get($user, 'preferred_username', Arr::get($user, 'given_name')),
            'name' => trim(Arr::get($user, 'given_name', '') . ' ' . Arr::get($user, 'family_name', '')) ?: null,
            'given_name' => Arr::get($user, 'given_name'),
            'family_name' => Arr::get($user, 'family_name'),
            'email' => Arr::get($user, 'email'),
            'gender' => Arr::get($user, 'gender'),
            'birthplace' => Arr::get($user, 'birthplace'),
            'birthcountry' => Arr::get($user, 'birthcountry'),
            'preferred_username' => Arr::get($user, 'preferred_username'),
            'avatar' => Arr::get($user, 'picture', null),
        ]);
    }

    /**
     * Generate logout URL for FranceConnect end session.
     */
    public function getLogoutUrl(string $idToken): string
    {
        $postLogout = urlencode($this->getConfig('logout_redirect'));

        return sprintf(
            '%s/session/end?post_logout_redirect_uri=%s&id_token_hint=%s',
            $this->getBaseUrl(),
            $postLogout,
            $idToken
        );
    }

    /**
     * Resolve base URL depending on environment config.
     */
    protected function getBaseUrl(): string
    {
        $env = $this->getConfig('environment') ?: config('app.env');

        return self::URLS[$env === 'production' ? 'production' : 'integration'];
    }
}
