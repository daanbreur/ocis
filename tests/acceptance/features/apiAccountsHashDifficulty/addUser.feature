@skipOnReva
Feature: add user
  As an admin
  I want to be able to add users and store their password with the full hash difficulty
  So that I can give people controlled individual access to resources on the ownCloud server

  Note - this feature is run in CI with ACCOUNTS_HASH_DIFFICULTY set to the default for production
  See https://github.com/owncloud/ocis/issues/1542 and https://github.com/owncloud/ocis/pull/839


  Scenario: admin creates a user
    When the user "Admin" creates a new user with the following attributes using the Graph API:
      | userName       | brand-new-user  |
      | displayName    | Brand New User  |
      | email          | new@example.org |
      | password       | %alt1%          |
    Then the HTTP status code should be "201"
    And user "brand-new-user" should exist
    And user "brand-new-user" should be able to upload file "filesForUpload/lorem.txt" to "lorem.txt"
