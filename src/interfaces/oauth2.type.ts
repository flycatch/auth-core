/**
 * Represents the supported OAuth2 providers for authentication integrations.
 *
 * Includes a comprehensive list of popular social, developer, business, media,
 * communication, gaming, financial, and custom providers.
 *
 * This type allows both predefined and custom provider strings to support flexible OAuth2 integrations.
 */
export type OAuth2Providers =
  // Major Social Platforms
  | "google"
  | "facebook"
  | "github"
  | "twitter"
  | "linkedin"
  | "instagram"
  | "microsoft"
  | "apple"
  | "amazon"

  // Developer & Tech Platforms
  | "gitlab"
  | "bitbucket"
  | "atlassian"
  | "jira"
  | "confluence"
  | "slack"
  | "discord"
  | "twitch"
  | "reddit"
  | "stackexchange"

  // Productivity & Business
  | "dropbox"
  | "box"
  | "salesforce"
  | "zendesk"
  | "asana"
  | "trello"
  | "notion"
  | "basecamp"

  // Media & Design
  | "spotify"
  | "pinterest"
  | "imgur"
  | "dribbble"
  | "behance"
  | "flickr"
  | "vimeo"
  | "deviantart"

  // Communication
  | "zoom"
  | "skype"
  | "line"
  | "kakao"
  | "wechat"

  // Gaming
  | "steam"
  | "epicgames"
  | "xbox"
  | "playstation"

  // Financial & E-commerce
  | "paypal"
  | "stripe"
  | "shopify"
  | "quickbooks"
  | "xero"

  // Location & Travel
  | "foursquare"
  | "uber"
  | "lyft"
  | "airbnb"

  // Health & Fitness
  | "fitbit"
  | "strava"
  | "runkeeper"

  // Government & Education
  | "auth0"
  | "okta"
  | "keycloak"
  | "edmodo"

  // Custom/Generic OAuth2
  | "oauth2"
  | "oidc"
  | string; // Allow any custom provider
