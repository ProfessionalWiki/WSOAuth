<?php

/**
 * Copyright 2022 Professional.Wiki
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
 * OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

namespace WSOAuth\AuthenticationProvider;

use GlobalVarConfig;
use MediaWiki\MediaWikiServices;
use MediaWiki\User\UserIdentity;
use MediaWiki\User\UserNameUtils;
use Wohali\OAuth2\Client\Provider\Discord;

/**
 * Class DiscordAuth
 * @package AuthenticationProvider
 */
class DiscordAuth implements AuthProvider {
	/**
	 * @var Discord
	 */
	private $provider;

	/**
	 * @var GlobalVarConfig
	 */
	private $config;

	/**
	 * @var UserNameUtils
	 */
	private $userNameUtils;

	/**
	 * @inheritDoc
	 */
	public function __construct( string $clientId, string $clientSecret, ?string $authUri, ?string $redirectUri ) {
		$this->provider = new Discord( [
			'clientId' => $clientId,
			'clientSecret' => $clientSecret,
			'redirectUri' => $redirectUri,
		] );

		$this->config = new GlobalVarConfig();
		$this->userNameUtils = MediaWikiServices::getInstance()->getUserNameUtils();
	}

	/**
	 * @inheritDoc
	 */
	public function login( ?string &$key, ?string &$secret, ?string &$authUrl ): bool {
		$authUrl = $this->provider->getAuthorizationUrl( [
			'scope' => [ 'identify', 'email' ],
			'prompt' => 'none'
		] );

		$secret = $this->provider->getState();

		// TOOD: not sure what should be done here:
		$key = (string)time();

		return true;
	}

	/**
	 * @inheritDoc
	 */
	public function logout( UserIdentity &$user ): void {
	}

	/**
	 * @inheritDoc
	 */
	public function getUser( string $key, string $secret, &$errorMessage ) {
		if ( !isset( $_GET['code'] ) ) {
			return false;
		}

		if ( !isset( $_GET['state'] ) || empty( $_GET['state'] ) || ( $_GET['state'] !== $secret ) ) {
			return false;
		}

		try {
			$token = $this->provider->getAccessToken( 'authorization_code', [ 'code' => $_GET['code'] ] );
			$user = $this->provider->getResourceOwner( $token );
			$userArray = $user->toArray();

			return [
				'name' => $user->getId(),
				'realname' => $this->getRealName( $user->getId(), $userArray['username'] ),
				'email' => $userArray['email']
			];
		} catch ( \Exception $e ) {
			return false;
		}
	}

	/**
	 * @inheritDoc
	 */
	public function saveExtraAttributes( int $id ): void {
	}

	private function getRealName( string $id, string $username ): string {
		$name = $this->formatRealName( $id, $username );

		if ( !$this->userNameUtils->isValid( $name ) ) {
			return $id;
		}

		return $name;
	}

	private function formatRealName( string $id, string $username ): string {
		return $this->makeUsernameValid( $username ) . " ($id)";
	}

	private function makeUsernameValid( string $username ): string {
		$legal = $this->config->get('LegalTitleChars');
		$invalid = $this->config->get('InvalidUsernameCharacters');
		$newUsername = preg_replace( "/([^$legal]|[$invalid]|\/)/", '-', $username );
		return ucfirst( trim( $newUsername ) );
	}

}
