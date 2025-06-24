# MSSP Client

A .NET client application for interacting with Mobile Signature Service Provider (MSSP) based on the ETSI TS 102 204 standard. This client enables mobile digital signature operations and certificate management for Vietnamese mobile digital signature services.

## Overview

The MSSP Client provides a simple interface to interact with mobile signature services, allowing applications to:
- Retrieve mobile user certificates
- Create digital signatures using mobile devices

This implementation is specifically designed for Vietnamese mobile signature infrastructure, supporting services like ViettelCA and other MSSP providers.

## Features

- **Certificate Registration**: Retrieve their digital certificates
- **Digital Signing**: Create digital signatures using mobile devices with user confirmation
- **Secure Communication**: Uses client certificate authentication and SSL/TLS
- **Cryptographic Operations**: Leverages BouncyCastle for advanced cryptographic functions

## Prerequisites

- .NET 9.0 or later
- Valid Application Provider (AP) credentials
- Client certificate for authentication (PKCS#12 format)
- Access to MSSP service endpoints

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd MSSPClient
```

2. Restore dependencies:
```bash
dotnet restore
```

3. Build the project:
```bash
dotnet build
```

## Configuration

### Required Credentials

Before using the client, you need to configure the following:

1. **Application Provider (AP) Credentials**:
   - `AP_ID`: Your application provider identifier (e.g., "http://ap.mobile-id.vn/viettelca")
   - `AP_PWD`: Your application provider password

2. **MSSP Information**:
   - `MSSP_ID`: Mobile Signature Service Provider identifier (e.g., "http://hmssp.mobile-id.vn")

3. **Client Certificate**:
   - Path to your PKCS#12 certificate file
   - Certificate password

### Service Endpoints

The client connects to the following service endpoints:
- **Signature Service**: `https://mpki1.ca.gov.vn:18083/soap/services/MSS_SignaturePort`
- **Registration Service**: `https://mpki1.ca.gov.vn:18083/soap/services/MSS_RegistrationPort`

## Usage

### Basic Example

```csharp
// Load client certificate
var cert = X509CertificateLoader.LoadPkcs12FromFile(
    "path/to/your/certificate.p12",
    "certificate_password"
);

// Configure credentials
string apId = "http://ap.mobile-id.vn/test"; //Change to your AP ID
string apPassword = "your_ap_password";
string msspId = "http://hmssp.mobile-id.vn";
string phoneNumber = "84xxxxxxxxx"; // Mobile number in international format
```

### Certificate Registration

```csharp
static async Task RegisterCertificateAsync()
{
    var client = new MSS_RegistrationTypeClient();
    
    // Configure client certificate authentication
    client.ClientCredentials.ClientCertificate.Certificate = cert;
    client.ClientCredentials.ServiceCertificate.SslCertificateAuthentication =
        new X509ServiceCertificateAuthentication
        {
            CertificateValidationMode = X509CertificateValidationMode.None,
            RevocationMode = X509RevocationMode.NoCheck,
        };

    var request = new MSS_RegistrationReqType
    {
        MajorVersion = "1",
        MinorVersion = "1",
        AP_Info = new MessageAbstractTypeAP_Info
        {
            AP_ID = apId,
            AP_PWD = apPassword,
            AP_TransID = Guid.NewGuid().ToString("N").Substring(0, 10), //Keep AP_TransID unchanged for 15 minutes to enable PIN caching.
            Instant = DateTime.UtcNow
        },
        MSSP_Info = new MessageAbstractTypeMSSP_Info
        {
            MSSP_ID = new MeshMemberType { URI = msspId },
            Instant = DateTime.UtcNow,
        },
        MobileUser = new MobileUserType
        {
            MSISDN = phoneNumber
        }
    };

    var response = await client.MSS_RegistrationAsync(request);
    
    if (response.MSS_RegistrationResp.Status.StatusCode.Value == "408")
    {
        // Success - certificate retrieved
        var certificate = response.MSS_RegistrationResp.CertificateResponse[0].X509Certificate;
        var userCert = X509CertificateLoader.LoadCertificate(certificate);
        Console.WriteLine($"Certificate Subject: {userCert.Subject}");
    }
}
```

### Digital Signing

```csharp
static async Task CreateSignatureAsync()
{
    var client = new MSS_SignatureTypeClient();
    
    // Configure client certificate authentication
    client.ClientCredentials.ClientCertificate.Certificate = cert;
    client.ClientCredentials.ServiceCertificate.SslCertificateAuthentication =
        new X509ServiceCertificateAuthentication
        {
            CertificateValidationMode = X509CertificateValidationMode.None,
            RevocationMode = X509RevocationMode.NoCheck,
        };

    // Prepare data to be signed
    byte[] message = Encoding.UTF8.GetBytes("Document content to sign");
    string hashAlgorithm = "SHA256";
    
    // Create hash using BouncyCastle
    var algId = new AlgorithmIdentifier(DigestUtilities.GetObjectIdentifier(hashAlgorithm), DerNull.Instance);
    var digest = DigestUtilities.GetDigest(hashAlgorithm);
    byte[] hash = new byte[digest.GetDigestSize()];
    digest.BlockUpdate(message, 0, message.Length);
    digest.DoFinal(hash, 0);
    
    var dInfo = new DigestInfo(algId, hash);
    byte[] hashedData = dInfo.GetDerEncoded();

    var request = new MSS_SignatureReqType
    {
        MajorVersion = "1",
        MinorVersion = "1",
        AP_Info = new MessageAbstractTypeAP_Info
        {
            AP_ID = apId,
            AP_PWD = apPassword,
            AP_TransID = Guid.NewGuid().ToString("N").Substring(0, 10),
            Instant = DateTime.UtcNow
        },
        MSSP_Info = new MessageAbstractTypeMSSP_Info
        {
            MSSP_ID = new MeshMemberType { URI = msspId },
            Instant = DateTime.UtcNow,
        },
        MobileUser = new MobileUserType
        {
            MSISDN = phoneNumber
        },
        DataToBeSigned = new DataType
        {
            MimeType = "application/octet-stream",
            Encoding = "base64",
            Value = Convert.ToBase64String(hashedData)
        },
        DataToBeDisplayed = new DataType
        {
            MimeType = "text/plain",
            Encoding = "UTF-8",
            Value = "Please confirm this signature request"
        },
        SignatureProfile = new mssURIType
        {
            mssURI = "http://mobile-id.vn/digitalSignature"
        },
        MSS_Format = new mssURIType
        {
            mssURI = "http://uri.etsi.org/TS102204/v1.1.2#PKCS1"
        },
        MessagingMode = MessagingModeType.synch,
        TimeOut = "300",
        AdditionalServices = new AdditionalServiceType[]
        {
            new AdditionalServiceType
            {
                Description = new mssURIType
                {
                    mssURI = "http://mobile-id.vn/MSSP/v1.0.0#signingCertificate"
                }
            },
            new AdditionalServiceType
            {
                Description = new mssURIType
                {
                    mssURI = "http://mobile-id.vn/MSSP/v1.0.0#signatureValidation"
                }
            }
        }
    };

    var response = await client.MSS_SignatureAsync(request);
    
    if (response.MSS_SignatureResp.Status.StatusCode.Value == "408")
    {
        // Success - signature created
        byte[] signature = response.MSS_SignatureResp.MSS_Signature.Item;
        Console.WriteLine($"Signature: {Convert.ToBase64String(signature)}");
    }
}
```

## Status Codes

Common status codes returned by the service:

- **408**: Success - Operation completed successfully
- **401**: Authentication failed
- **402**: Authorization failed  
- **403**: User not found or not registered
- **404**: Service not available
- **405**: User cancelled the operation
- **406**: Operation timeout
- **422**: Invalid request format

## Dependencies

- **BouncyCastle.Cryptography** (2.6.1): Advanced cryptographic operations
- **System.ServiceModel.Http** (8.*): HTTP-based WCF services
- **System.ServiceModel.NetTcp** (8.*): TCP-based WCF services  
- **System.ServiceModel.Primitives** (8.*): Core WCF functionality

## Project Structure

```
MSSPClient/
├── Program.cs                          # Main application entry point
├── MSSPClient.csproj                   # Project configuration
├── MSSPClient.sln                      # Solution file
├── MSS_SignaturePort.wsdl              # Service interface definition
├── ServiceReference/                   # Generated service client code
│   ├── MSS_SignaturePort.cs           # Generated client classes
│   └── dotnet-svcutil.params.json     # Service generation parameters
├── bin/                               # Build output
└── obj/                               # Build intermediate files
```

## Security Considerations

- Always use HTTPS endpoints in production
- Protect client certificates and private keys
- Validate server certificates in production environments
- Use secure storage for AP credentials
- Implement proper error handling and logging
- Consider implementing retry mechanisms for network failures

## Error Handling

The client includes basic error handling for common scenarios:

```csharp
try
{
    var response = await client.MSS_SignatureAsync(request);
    
    switch (response.MSS_SignatureResp.Status.StatusCode.Value)
    {
        case "408":
            // Success
            break;
        case "405":
            Console.WriteLine("User cancelled the operation");
            break;
        case "406":
            Console.WriteLine("Operation timeout");
            break;
        default:
            Console.WriteLine($"Error: {response.MSS_SignatureResp.Status.StatusMessage}");
            break;
    }
}
catch (Exception ex)
{
    Console.WriteLine($"Service error: {ex.Message}");
}
```

## Running the Application

```bash
dotnet run
```

The application will execute both certificate registration and signature creation examples using the configured credentials.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the GNU License - see the LICENSE file for details.

## Support

For issues related to:
- **MSSP Service**: Contact your Mobile Signature Service Provider
- **Client Implementation**: Create an issue in this repository
- **Certificates**: Contact your Certificate Authority (CA)

## References

- [ETSI TS 102 204](https://www.etsi.org/deliver/etsi_ts/102200_102299/102204/01.01.02_60/ts_102204v010102p.pdf) - Mobile Signature Service Standard
- [BouncyCastle Cryptography](https://www.bouncycastle.org/csharp/)



If this repository is helpful to you, consider supporting me with a coffee.

<a href="https://buymeacoffee.com/txaopc" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" width="170px"></a>

or
<a href="https://github.com/user-attachments/assets/4f103c82-7938-4865-927f-a6deab3f29cd" target="_blank">QR Code</a>