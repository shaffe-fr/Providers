<?php

namespace SocialiteProviders\FranceConnect;

use GuzzleHttp\RequestOptions;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use Laravel\Socialite\Two\InvalidStateException;
use SocialiteProviders\Manager\OAuth2\AbstractProvider;

class Provider extends AbstractProvider
{
    /**
     * API URLs.
     */
    public const PROD_BASE_URL = 'https://oidc.franceconnect.gouv.fr/api/v2';

    public const TEST_BASE_URL = 'https://fcp-low.integ01.dev-franceconnect.fr/api/v2';

    public const IDENTIFIER = 'FRANCECONNECT';

    protected $scopes = [
        'openid',
        'profile',
        'email',
    ];

    protected $scopeSeparator = ' ';

    /**
     * Return API Base URL.
     *
     * @return string
     */
    protected function getBaseUrl(): string
    {
        return config('app.env') === 'production' ? self::PROD_BASE_URL : self::TEST_BASE_URL;
    }

    public static function additionalConfigKeys(): array
    {
        return ['logout_redirect'];
    }

    protected function getAuthUrl($state): string
    {
        //It is used to prevent replay attacks
        $this->parameters['nonce'] = Str::random(22);

        return $this->buildAuthUrlFromBase($this->getBaseUrl() . '/authorize', $state);
    }

    /**
     * {@inheritdoc}
     */
    protected function getCodeFields($state = null): array
    {
        $fields = parent::getCodeFields($state);

        $fields['acr_values'] = 'eidas1';
        $fields['prompt'] = 'consent';

        return $fields;
    }

    protected function getTokenUrl(): string
    {
        return $this->getBaseUrl() . '/token';
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessTokenResponse($code)
    {
        $response = $this->getHttpClient()->post($this->getBaseUrl() . '/token', [
            RequestOptions::HEADERS     => ['Authorization' => 'Basic ' . base64_encode($this->clientId . ':' . $this->clientSecret)],
            RequestOptions::FORM_PARAMS => $this->getTokenFields($code),
        ]);

        return json_decode((string) $response->getBody(), true);
    }

    /**
     * {@inheritdoc}
     */
    public function user()
    {
        if ($this->hasInvalidState()) {
            throw new InvalidStateException;
        }

        $response = $this->getAccessTokenResponse($this->getCode());

        $user = $this->mapUserToObject($this->getUserByToken(
            $token = Arr::get($response, 'access_token')
        ));

        //store tokenId session for logout url generation
        $this->request->session()->put('fc_token_id', Arr::get($response, 'id_token'));

        return $user->setTokenId(Arr::get($response, 'id_token'))
            ->setToken($token)
            ->setRefreshToken(Arr::get($response, 'refresh_token'))
            ->setExpiresIn(Arr::get($response, 'expires_in'));
    }

    /**
     * {@inheritdoc}
     */
    protected function getUserByToken($token)
    {
        $response = $this->getHttpClient()->get($this->getBaseUrl() . '/userinfo', [
            RequestOptions::HEADERS => [
                'Authorization' => 'Bearer ' . $token,
            ],
        ]);

        return json_decode((string) $response->getBody(), true);
    }

    /**
     * {@inheritdoc}
     */
    protected function mapUserToObject(array $user)
    {
        return (new User)->setRaw($user)->map([
            'id'                     => $user['sub'],
            'given_name'             => $user['given_name'],
            'family_name'            => $user['family_name'],
            'gender'                 => $user['gender'],
            'birthplace'             => $user['birthplace'],
            'birthcountry'           => $user['birthcountry'],
            'email'                  => $user['email'],
            'preferred_username'     => $user['preferred_username'],
        ]);
    }

    /**
     *  Generate logout URL for redirection to FranceConnect.
     */
    public function generateLogoutURL(): string
    {
        $params = [
            'post_logout_redirect_uri' => $this->getConfig('logout_redirect'),
            'id_token_hint'            => $this->request->session()->get('fc_token_id'),
        ];

        return $this->getBaseUrl() . '/session/end?' . http_build_query($params);
    }
}
