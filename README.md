# Trimble OAuth2 OmniAuth Strategy

An OmniAuth OAuth2 strategy for authenticating with Trimble Identity services. This gem extracts user information from JWT ID tokens returned by Trimble's OAuth2 implementation.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'omniauth-trimble-oauth2'
```

Or install it yourself as:

```bash
gem install omniauth-trimble-oauth2
```

## Usage

### For Devise Users

Add to your `config/initializers/devise.rb`:

```ruby
config.omniauth :trimble_oauth2, ENV['TRIMBLE_CLIENT_ID'], ENV['TRIMBLE_CLIENT_SECRET']
```

Make sure your User model includes the provider:

```ruby
class User < ApplicationRecord
  devise :omniauthable, omniauth_providers: [:trimble_oauth2]
end
```

### For Standalone OmniAuth

Add the following to your `config/initializers/omniauth.rb`:

```ruby
Rails.application.config.middleware.use OmniAuth::Builder do
  provider :trimble_oauth2, ENV['TRIMBLE_CLIENT_ID'], ENV['TRIMBLE_CLIENT_SECRET']
end
```

### Environment Variables

Set your Trimble OAuth2 application credentials:

```bash
export TRIMBLE_CLIENT_ID="your_client_id"
export TRIMBLE_CLIENT_SECRET="your_client_secret"
```

### Routes and Callback Handling

The strategy will create these routes:
- `/users/auth/trimble_oauth2` - Initiates OAuth flow
- `/users/auth/trimble_oauth2/callback` - Handles OAuth callback

Handle the callback in your controller:

```ruby
class SessionsController < ApplicationController
  def omniauth
    auth_hash = request.env['omniauth.auth']
    
    # Access user information from JWT ID token
    user_id = auth_hash.uid                    # Trimble user ID
    user_info = auth_hash.info
    
    # Available user info:
    puts user_info.name        # Full name
    puts user_info.email       # Email address  
    puts user_info.first_name  # Given name
    puts user_info.last_name   # Family name
    
    # Additional info in extras:
    puts auth_hash.extra.location  # Data region (e.g., 'ap-au')
    puts auth_hash.extra.picture   # Profile picture URL
    
    # Raw JWT claims available in auth_hash.extra.raw_info
  end
end
```

### Configuration Options

You can pass additional parameters at runtime:

```ruby
# Pass additional scopes via URL parameter
link_to "Sign in with Trimble", "/users/auth/trimble_oauth2?scope=openid%20profile"

# Configure in initializer
provider :trimble_oauth2, client_id, client_secret,
  client_options: {
    site: 'https://id.trimble.com'  # Uses Trimble's OAuth2 endpoints
  }
```

## OAuth2 Flow

1. User visits `/users/auth/trimble_oauth2`
2. User is redirected to `https://id.trimble.com/oauth/authorize`
3. After authentication, user is redirected to `/users/auth/trimble_oauth2/callback`
4. Strategy exchanges code for access token and JWT ID token
5. User information is extracted from JWT ID token (no additional API calls needed)
6. Your application receives the authentication hash

## Trimble API Endpoints

This strategy uses Trimble's OAuth2 endpoints:
- **Authorization URL:** `https://id.trimble.com/oauth/authorize`
- **Token URL:** `https://id.trimble.com/oauth/token`

## Dependencies

- `omniauth-oauth2` (~> 1.7.1)
- `jwt` (~> 2.0) - For decoding Trimble's JWT ID tokens

## Development

After checking out the repo, run `bin/setup` to install dependencies. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and the created tag, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/[USERNAME]/trimble-oauth2-omniauth-strategy.
