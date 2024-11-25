# SocialiteProviders / FranceConnect

A Laravel Socialite provider for FranceConnect (OpenID Connect v2), supporting both production and integration environments.

---

## Installation

Install via Composer:

```bash
composer require socialiteproviders/franceconnect
```

---

## Configuration

### 1. Add to `config/services.php`

```php
'franceconnect' => [
    'client_id'        => env('FC_CLIENT_ID'),
    'client_secret'    => env('FC_CLIENT_SECRET'),
    'redirect'         => env('FC_REDIRECT_URI'),
    'logout_redirect'  => env('FC_LOGOUT_REDIRECT_URI'),
],
```

### 2. Add to `.env`

```ini
FC_CLIENT_ID=
FC_CLIENT_SECRET=
FC_REDIRECT_URI=
FC_LOGOUT_REDIRECT_URI=
```

---

## Register the Provider

### Laravel 11+

In Laravel 11, the `EventServiceProvider` is removed by default. Instead, register Socialite providers in `AppServiceProvider`:

```php
use Illuminate\Support\Facades\Event;
use SocialiteProviders\Manager\SocialiteWasCalled;

public function boot()
{
    Event::listen(SocialiteWasCalled::class, function ($event) {
        $event->extendSocialite(
            'franceconnect',
            \SocialiteProviders\FranceConnect\Provider::class
        );
    });
}
```

### Laravel 10 and Below

In `app/Providers/EventServiceProvider.php`:

```php
protected $listen = [
    \SocialiteProviders\Manager\SocialiteWasCalled::class => [
        \SocialiteProviders\FranceConnect\FranceConnectExtendSocialite::class . '@handle',
    ],
];
```

---

## Usage

Use FranceConnect like any other Socialite driver:

```php
use Laravel\Socialite\Facades\Socialite;

// Redirect to FranceConnect
default public function redirectToFranceConnect()
{
    return Socialite::driver('franceconnect')->redirect();
}

// Handle FranceConnect callback
public function handleFranceConnectCallback()
{
    $user = Socialite::driver('franceconnect')
        ->stateless() // Remove for session-based state/nonce handling
        ->user();

    // Save ID token for logout later
    session(['fc_id_token' => $user->refreshToken]);

    // Access tokens:
    // $user->token, $user->refreshToken, $user->refreshToken, $user->getRaw()
}
```

> **Tip:** Remove `stateless()` if you want automatic state and nonce validation.

---

## Logout

FranceConnect Single Logout (SLO) uses the OpenID end-session endpoint.

The driver provides:

```php
getLogoutUrl(string $idToken): string
```

### Example

First, ensure you store the `id_token` after login:

```php
session(['fc_id_token' => $user->refreshToken]);
```

Then generate the logout URL:

```php
use Laravel\Socialite\Facades\Socialite;

public function logoutFromFranceConnect()
{
    $idToken = session('fc_id_token');

    if (!$idToken) {
        abort(400, 'No ID Token found in session.');
    }

    $logoutUrl = Socialite::driver('franceconnect')
        ->getLogoutUrl($idToken);

    return redirect()->away($logoutUrl);
}
```

> ✅ The `id_token` is mandatory for FranceConnect logout.

---
