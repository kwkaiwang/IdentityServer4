// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using FluentAssertions;
using IdentityModel;
using IdentityModel.Client;
using IdentityServer.IntegrationTests.Clients.Setup;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Xunit;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace IdentityServer.IntegrationTests.Clients
{
    public class CustomTokenResponseClients
    {
        private const string TokenEndpoint = "https://server/connect/token";

        private readonly HttpClient _client;

        public CustomTokenResponseClients()
        {
            var builder = new WebHostBuilder()
                .UseStartup<StartupWithCustomTokenResponses>();
            var server = new TestServer(builder);

            _client = server.CreateClient();
        }

        [Fact]
        public async Task Resource_owner_success_should_return_custom_response()
        {
            var response = await _client.RequestPasswordTokenAsync(new PasswordTokenRequest
            {
                Address = TokenEndpoint,
                ClientId = "roclient",
                ClientSecret = "secret",

                UserName = "bob",
                Password = "bob",
                Scope = "api1"
            });

            // raw fields
            var fields = GetFields(response);
            fields.Should().ContainKey("string_value").WhoseValue.ToString().Should().Be("some_string");
            ((JsonElement)fields["int_value"]).GetInt64().Should().Be(42);

            object temp;
            fields.TryGetValue("identity_token", out temp).Should().BeFalse();
            fields.TryGetValue("refresh_token", out temp).Should().BeFalse();
            fields.TryGetValue("error", out temp).Should().BeFalse();
            fields.TryGetValue("error_description", out temp).Should().BeFalse();
            fields.TryGetValue("token_type", out temp).Should().BeTrue();
            fields.TryGetValue("expires_in", out temp).Should().BeTrue();

            var responseObject = (JsonElement)fields["dto"];
            responseObject.Should().NotBeNull();

            var responseDto = GetDto(responseObject);
            var dto = CustomResponseDto.Create;

            responseDto.string_value.Should().Be(dto.string_value);
            responseDto.int_value.Should().Be(dto.int_value);
            responseDto.nested.string_value.Should().Be(dto.nested.string_value);
            responseDto.nested.int_value.Should().Be(dto.nested.int_value);


            // token client response
            response.IsError.Should().Be(false);
            response.ExpiresIn.Should().Be(3600);
            response.TokenType.Should().Be("Bearer");
            response.IdentityToken.Should().BeNull();
            response.RefreshToken.Should().BeNull();
            

            // token content
            var payload = GetPayload(response);
            payload.Count().Should().Be(12);
            payload.Should().ContainKey("iss").WhoseValue.ToString().Should().Be("https://idsvr4");
            payload.Should().ContainKey("client_id").WhoseValue.ToString().Should().Be("roclient");
            payload.Should().ContainKey("sub").WhoseValue.ToString().Should().Be("bob");
            payload.Should().ContainKey("idp").WhoseValue.ToString().Should().Be("local");

            payload["aud"].ToString().Should().Be("api");

            var scopes = ((JsonElement)payload["scope"]).EnumerateArray();
            scopes.First().ToString().Should().Be("api1");

            var amr = ((JsonElement) payload["amr"]).EnumerateArray();
            amr.Count().Should().Be(1);
            amr.First().ToString().Should().Be("password");
        }

        [Fact]
        public async Task Resource_owner_failure_should_return_custom_error_response()
        {
            var response = await _client.RequestPasswordTokenAsync(new PasswordTokenRequest
            {
                Address = TokenEndpoint,
                ClientId = "roclient",
                ClientSecret = "secret",

                UserName = "bob",
                Password = "invalid",
                Scope = "api1"
            });

            // raw fields
            var fields = GetFields(response);
            fields.Should().ContainKey("string_value").WhoseValue.ToString().Should().BeEquivalentTo("some_string"); ;
            ((JsonElement)fields["int_value"]).GetInt64().Should().Be(42);

            object temp;
            fields.TryGetValue("identity_token", out temp).Should().BeFalse();
            fields.TryGetValue("refresh_token", out temp).Should().BeFalse();
            fields.TryGetValue("error", out temp).Should().BeTrue();
            fields.TryGetValue("error_description", out temp).Should().BeTrue();
            fields.TryGetValue("token_type", out temp).Should().BeFalse();
            fields.TryGetValue("expires_in", out temp).Should().BeFalse();

            var responseObject = (JsonElement)fields["dto"];
            responseObject.Should().NotBeNull();

            var responseDto = GetDto(responseObject);
            var dto = CustomResponseDto.Create;

            responseDto.string_value.Should().Be(dto.string_value);
            responseDto.int_value.Should().Be(dto.int_value);
            responseDto.nested.string_value.Should().Be(dto.nested.string_value);
            responseDto.nested.int_value.Should().Be(dto.nested.int_value);


            // token client response
            response.IsError.Should().Be(true);
            response.Error.Should().Be("invalid_grant");
            response.ErrorDescription.Should().Be("invalid_credential");
            response.ExpiresIn.Should().Be(0);
            response.TokenType.Should().BeNull();
            response.IdentityToken.Should().BeNull();
            response.RefreshToken.Should().BeNull();
        }

        [Fact]
        public async Task Extension_grant_success_should_return_custom_response()
        {
            var response = await _client.RequestTokenAsync(new TokenRequest
            {
                Address = TokenEndpoint,
                GrantType = "custom",

                ClientId = "client.custom",
                ClientSecret = "secret",

                Parameters =
                {
                    { "scope", "api1" },
                    { "outcome", "succeed"}
                }
            });


            // raw fields
            var fields = GetFields(response);
            fields.Should().ContainKey("string_value");
            ((JsonElement)fields["int_value"]).GetInt64().Should().Be(42);

            object temp;
            fields.TryGetValue("identity_token", out temp).Should().BeFalse();
            fields.TryGetValue("refresh_token", out temp).Should().BeFalse();
            fields.TryGetValue("error", out temp).Should().BeFalse();
            fields.TryGetValue("error_description", out temp).Should().BeFalse();
            fields.TryGetValue("token_type", out temp).Should().BeTrue();
            fields.TryGetValue("expires_in", out temp).Should().BeTrue();

            var responseObject = (JsonElement)fields["dto"];
            responseObject.Should().NotBeNull();

            var responseDto = GetDto(responseObject);
            var dto = CustomResponseDto.Create;

            responseDto.string_value.Should().Be(dto.string_value);
            responseDto.int_value.Should().Be(dto.int_value);
            responseDto.nested.string_value.Should().Be(dto.nested.string_value);
            responseDto.nested.int_value.Should().Be(dto.nested.int_value);


            // token client response
            response.IsError.Should().Be(false);
            response.ExpiresIn.Should().Be(3600);
            response.TokenType.Should().Be("Bearer");
            response.IdentityToken.Should().BeNull();
            response.RefreshToken.Should().BeNull();


            // token content
            var payload = GetPayload(response);
            payload.Count().Should().Be(12);
            payload.Should().ContainKey("iss"); //"https://idsvr4"
            payload.Should().ContainKey("client_id").WhoseValue.ToString().Should().BeEquivalentTo("client.custom");
            payload.Should().ContainKey("sub").WhoseValue.ToString().Should().BeEquivalentTo("bob"); ;//, "bob"
            payload.Should().ContainKey("idp").WhoseValue.ToString().Should().BeEquivalentTo("local");

            //payload["aud"].Should().Be("api");
            payload.Should().ContainKey("aud").WhoseValue.ToString().Should().BeEquivalentTo("api");

            var scopes = (JsonElement) payload["scope"];
            scopes[0].ToString().Should().Be("api1");

            var amr = ((JsonElement)payload["amr"]).EnumerateArray();
            amr.Count().Should().Be(1);
            amr.First().ToString().Should().Be("custom");

        }

        [Fact]
        public async Task Extension_grant_failure_should_return_custom_error_response()
        {
            var response = await _client.RequestTokenAsync(new TokenRequest
            {
                Address = TokenEndpoint,
                GrantType = "custom",

                ClientId = "client.custom",
                ClientSecret = "secret",

                Parameters =
                {
                    { "scope", "api1" },
                    { "outcome", "fail"}
                }
            });


            // raw fields
            var fields = GetFields(response);
            fields.Should().ContainKey("string_value");
            (((JsonElement)fields["int_value"]).GetInt64()).Should().Be(42);

            object temp;
            fields.TryGetValue("identity_token", out temp).Should().BeFalse();
            fields.TryGetValue("refresh_token", out temp).Should().BeFalse();
            fields.TryGetValue("error", out temp).Should().BeTrue();
            fields.TryGetValue("error_description", out temp).Should().BeTrue();
            fields.TryGetValue("token_type", out temp).Should().BeFalse();
            fields.TryGetValue("expires_in", out temp).Should().BeFalse();

            var responseObject = (JsonElement) fields["dto"];
            responseObject.Should().NotBeNull();

            var responseDto = GetDto(responseObject);
            var dto = CustomResponseDto.Create;

            responseDto.string_value.Should().Be(dto.string_value);
            responseDto.int_value.Should().Be(dto.int_value);
            responseDto.nested.string_value.Should().Be(dto.nested.string_value);
            responseDto.nested.int_value.Should().Be(dto.nested.int_value);


            // token client response
            response.IsError.Should().Be(true);
            response.Error.Should().Be("invalid_grant");
            response.ErrorDescription.Should().Be("invalid_credential");
            response.ExpiresIn.Should().Be(0);
            response.TokenType.Should().BeNull();
            response.IdentityToken.Should().BeNull();
            response.RefreshToken.Should().BeNull();
        }

        private CustomResponseDto GetDto(JsonElement e)
        {
            return e.Deserialize<CustomResponseDto>();
        }
        private CustomResponseDto GetDto(JsonObject responseObject)
        {
            return responseObject.Deserialize<CustomResponseDto>();
        }

        private Dictionary<string, object> GetFields(TokenResponse response)
        {
            return response.Json?.Deserialize<Dictionary<string, object>>();
        }

        private Dictionary<string, object> GetPayload(TokenResponse response)
        {
            var token = response.AccessToken.Split('.').Skip(1).Take(1).First();
            var text = Encoding.UTF8.GetString(Base64Url.Decode(token));
            var dictionary = JsonSerializer.Deserialize<Dictionary<string, object>>(text);

            return dictionary;
        }
    }
}