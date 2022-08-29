// Package docs GENERATED BY THE COMMAND ABOVE; DO NOT EDIT
// This file was generated by swaggo/swag
package docs

import "github.com/swaggo/swag"

const docTemplate_swagger = `{
    "schemes": {{ marshal .Schemes }},
    "swagger": "2.0",
    "info": {
        "description": "{{escape .Description}}",
        "title": "{{.Title}}",
        "termsOfService": "https://www.cossacklabs.com/acra/",
        "contact": {
            "name": "Cossack Labs dev team",
            "url": "cossacklabs.com",
            "email": "dev@cossacklabs.com"
        },
        "license": {
            "name": "Acra Evaluation license",
            "url": "https://www.cossacklabs.com/acra/"
        },
        "version": "{{.Version}}"
    },
    "host": "{{.Host}}",
    "basePath": "{{.BasePath}}",
    "paths": {
        "/v2/decrypt": {
            "get": {
                "description": "Decrypt AcraStruct with specified AdditionalContext or ClientID from connection",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "summary": "Decrypt AcraStruct",
                "parameters": [
                    {
                        "description": "Binary data encoded as Base64 string",
                        "name": "data",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "type": "string"
                        }
                    },
                    {
                        "description": "AdditionalContext",
                        "name": "zone_id",
                        "in": "body",
                        "schema": {
                            "type": "string"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/http_api.encryptionHTTPResponse"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/http_api.HTTPError"
                        }
                    },
                    "422": {
                        "description": "Unprocessable Entity",
                        "schema": {
                            "$ref": "#/definitions/http_api.HTTPError"
                        }
                    }
                }
            }
        },
        "/v2/decryptSearchable": {
            "get": {
                "description": "Decrypt searchable AcraStruct with specified AdditionalContext or ClientID from connection",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "summary": "Decrypt searchable AcraStruct",
                "parameters": [
                    {
                        "description": "Binary data encoded as Base64 string",
                        "name": "data",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "type": "string"
                        }
                    },
                    {
                        "description": "AdditionalContext",
                        "name": "zone_id",
                        "in": "body",
                        "schema": {
                            "type": "string"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/http_api.encryptionHTTPResponse"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/http_api.HTTPError"
                        }
                    },
                    "422": {
                        "description": "Unprocessable Entity",
                        "schema": {
                            "$ref": "#/definitions/http_api.HTTPError"
                        }
                    }
                }
            }
        },
        "/v2/decryptSym": {
            "get": {
                "description": "Decrypt AcraBlock with specified AdditionalContext or ClientID from connection",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "summary": "Decrypt AcraBlock",
                "parameters": [
                    {
                        "description": "Binary data encoded as Base64 string",
                        "name": "data",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "type": "string"
                        }
                    },
                    {
                        "description": "AdditionalContext",
                        "name": "zone_id",
                        "in": "body",
                        "schema": {
                            "type": "string"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/http_api.encryptionHTTPResponse"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/http_api.HTTPError"
                        }
                    },
                    "422": {
                        "description": "Unprocessable Entity",
                        "schema": {
                            "$ref": "#/definitions/http_api.HTTPError"
                        }
                    }
                }
            }
        },
        "/v2/decryptSymSearchable": {
            "get": {
                "description": "Decrypt searchable AcraBlock with specified AdditionalContext or ClientID from connection",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "summary": "Decrypt searchable AcraBlock",
                "parameters": [
                    {
                        "description": "Binary data encoded as Base64 string",
                        "name": "data",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "type": "string"
                        }
                    },
                    {
                        "description": "AdditionalContext",
                        "name": "zone_id",
                        "in": "body",
                        "schema": {
                            "type": "string"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/http_api.encryptionHTTPResponse"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/http_api.HTTPError"
                        }
                    },
                    "422": {
                        "description": "Unprocessable Entity",
                        "schema": {
                            "$ref": "#/definitions/http_api.HTTPError"
                        }
                    }
                }
            }
        },
        "/v2/detokenize": {
            "get": {
                "description": "Detokenize data according to data type",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "summary": "Detokenize data",
                "parameters": [
                    {
                        "description": "String or Base64 encoded binary value, or integer",
                        "name": "data",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "type": "string"
                        }
                    },
                    {
                        "description": "AdditionalContext",
                        "name": "zone_id",
                        "in": "body",
                        "schema": {
                            "type": "string"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/http_api.tokenizationHTTPResponse"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/http_api.HTTPError"
                        }
                    },
                    "422": {
                        "description": "Unprocessable Entity",
                        "schema": {
                            "$ref": "#/definitions/http_api.HTTPError"
                        }
                    }
                }
            }
        },
        "/v2/encrypt": {
            "get": {
                "description": "Encrypt data with specified AdditionalContext or ClientID from connection",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "summary": "Encrypt with AcraStruct",
                "parameters": [
                    {
                        "description": "Binary data encoded as Base64 string",
                        "name": "data",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "type": "string"
                        }
                    },
                    {
                        "description": "AdditionalContext",
                        "name": "zone_id",
                        "in": "body",
                        "schema": {
                            "type": "string"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/http_api.encryptionHTTPResponse"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/http_api.HTTPError"
                        }
                    },
                    "422": {
                        "description": "Unprocessable Entity",
                        "schema": {
                            "$ref": "#/definitions/http_api.HTTPError"
                        }
                    }
                }
            }
        },
        "/v2/encryptSearchable": {
            "get": {
                "description": "Encrypt data with searchable AcraStruct with specified AdditionalContext or ClientID from connection",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "summary": "Encrypt with searchable AcraStruct",
                "parameters": [
                    {
                        "description": "Binary data encoded as Base64 string",
                        "name": "data",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "type": "string"
                        }
                    },
                    {
                        "description": "AdditionalContext",
                        "name": "zone_id",
                        "in": "body",
                        "schema": {
                            "type": "string"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/http_api.encryptionHTTPResponse"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/http_api.HTTPError"
                        }
                    },
                    "422": {
                        "description": "Unprocessable Entity",
                        "schema": {
                            "$ref": "#/definitions/http_api.HTTPError"
                        }
                    }
                }
            }
        },
        "/v2/encryptSym": {
            "get": {
                "description": "Encrypt data with AcraBlock with specified AdditionalContext or ClientID from connection",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "summary": "Encrypt with AcraBlock",
                "parameters": [
                    {
                        "description": "Binary data encoded as Base64 string",
                        "name": "data",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "type": "string"
                        }
                    },
                    {
                        "description": "AdditionalContext",
                        "name": "zone_id",
                        "in": "body",
                        "schema": {
                            "type": "string"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/http_api.encryptionHTTPResponse"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/http_api.HTTPError"
                        }
                    },
                    "422": {
                        "description": "Unprocessable Entity",
                        "schema": {
                            "$ref": "#/definitions/http_api.HTTPError"
                        }
                    }
                }
            }
        },
        "/v2/encryptSymSearchable": {
            "get": {
                "description": "Encrypt data with searchable AcraBlock with specified AdditionalContext or ClientID from connection",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "summary": "Encrypt with searchable AcraBlock",
                "parameters": [
                    {
                        "description": "Binary data encoded as Base64 string",
                        "name": "data",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "type": "string"
                        }
                    },
                    {
                        "description": "AdditionalContext",
                        "name": "zone_id",
                        "in": "body",
                        "schema": {
                            "type": "string"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/http_api.encryptionHTTPResponse"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/http_api.HTTPError"
                        }
                    },
                    "422": {
                        "description": "Unprocessable Entity",
                        "schema": {
                            "$ref": "#/definitions/http_api.HTTPError"
                        }
                    }
                }
            }
        },
        "/v2/generateQueryHash": {
            "get": {
                "description": "generates hash for data that may be used as blind index",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "summary": "Generates hash",
                "parameters": [
                    {
                        "description": "Binary data encoded as Base64 string",
                        "name": "data",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "type": "string"
                        }
                    },
                    {
                        "description": "AdditionalContext",
                        "name": "zone_id",
                        "in": "body",
                        "schema": {
                            "type": "string"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/http_api.encryptionHTTPResponse"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/http_api.HTTPError"
                        }
                    },
                    "422": {
                        "description": "Unprocessable Entity",
                        "schema": {
                            "$ref": "#/definitions/http_api.HTTPError"
                        }
                    }
                }
            }
        },
        "/v2/tokenize": {
            "get": {
                "description": "Tokenize data according to data type",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "summary": "Tokenize data",
                "parameters": [
                    {
                        "description": "String or Base64 encoded binary value, or integer",
                        "name": "data",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "type": "string"
                        }
                    },
                    {
                        "description": "AdditionalContext",
                        "name": "zone_id",
                        "in": "body",
                        "schema": {
                            "type": "string"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/http_api.tokenizationHTTPResponse"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/http_api.HTTPError"
                        }
                    },
                    "422": {
                        "description": "Unprocessable Entity",
                        "schema": {
                            "$ref": "#/definitions/http_api.HTTPError"
                        }
                    }
                }
            }
        }
    },
    "definitions": {
        "http_api.HTTPError": {
            "type": "object",
            "properties": {
                "code": {
                    "type": "integer",
                    "example": 400
                },
                "message": {
                    "type": "string",
                    "example": "invalid request body"
                }
            }
        },
        "http_api.encryptionHTTPResponse": {
            "type": "object",
            "properties": {
                "data": {
                    "type": "string",
                    "format": "base64",
                    "example": "ZGF0YQo="
                }
            }
        },
        "http_api.tokenizationHTTPResponse": {
            "type": "object",
            "properties": {
                "data": {
                    "type": "string"
                }
            }
        }
    }
}`

// SwaggerInfo_swagger holds exported Swagger Info so clients can modify it
var SwaggerInfo_swagger = &swag.Spec{
	Version:          "",
	Host:             "",
	BasePath:         "/v2",
	Schemes:          []string{},
	Title:            "Acra-Translator",
	Description:      "AcraTranslator is a lightweight server that receives AcraStructs/AcraBlocks and returns the decrypted data",
	InfoInstanceName: "swagger",
	SwaggerTemplate:  docTemplate_swagger,
}

func init() {
	swag.Register(SwaggerInfo_swagger.InstanceName(), SwaggerInfo_swagger)
}
