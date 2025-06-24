// See https://aka.ms/new-console-template for more information
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using ServiceReference;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Channels;
using System.ServiceModel.Security;
using System.Text;

static async Task TestGetCertAsync()
{

    // Example of loading a certificate from a file
    var cert = X509CertificateLoader.LoadPkcs12FromFile(
        "D:\\projects\\vgca\\MPKIToolKit\\Deploy\\mpkicrypto-v1.0.16-24.07.2023\\cert-ap-test\\3108937_VGCA_Application_Provider_certificate.p12",
        "123456"
    );
    Console.WriteLine($"Loaded certificate with thumbprint: {cert.Thumbprint}");


    String ApId = "http://ap.mobile-id.vn/viettelca";        // Replace with your actual AP_ID
    String ApPassword = "5Ge2GSA3";   // Replace with your actual AP_PWD

    String msspId = "http://hmssp.mobile-id.vn"; // Replace with your actual MSSP_ID

    String phoneNumber = "84962594424"; // Replace with actual phone number

    ServiceReference.MSS_RegistrationTypeClient client = new ServiceReference.MSS_RegistrationTypeClient();
    client.ClientCredentials.Windows.ClientCredential = System.Net.CredentialCache.DefaultNetworkCredentials;
    client.ChannelFactory.Credentials.ServiceCertificate.SslCertificateAuthentication =
    client.ClientCredentials.ServiceCertificate.SslCertificateAuthentication =
    new X509ServiceCertificateAuthentication
    {
        CertificateValidationMode = X509CertificateValidationMode.None,
        RevocationMode = X509RevocationMode.NoCheck,
    };
    client.ClientCredentials.ClientCertificate.Certificate = cert;
    client.ChannelFactory.Credentials.ClientCertificate.Certificate = cert;

    ServiceReference.MessageAbstractTypeAP_Info apInfo = new ServiceReference.MessageAbstractTypeAP_Info
    {
        AP_ID = ApId,
        AP_PWD = ApPassword,
        AP_TransID = Guid.NewGuid().ToString("N").Substring(0, 10), // Generate a random transaction ID
        Instant = DateTime.UtcNow
    };

    ServiceReference.MessageAbstractTypeMSSP_Info messageAbstractTypeMSSP_Info = new ServiceReference.MessageAbstractTypeMSSP_Info
    {
        MSSP_ID = new ServiceReference.MeshMemberType { URI = msspId },
        Instant = DateTime.UtcNow,
    };

    ServiceReference.MobileUserType mobileUser = new ServiceReference.MobileUserType
    {
        MSISDN = phoneNumber // Use the phone number directly
    };

    ServiceReference.MSS_RegistrationReqType request = new ServiceReference.MSS_RegistrationReqType
    {
        MajorVersion = BigInteger.ValueOf(1L).ToString(),
        MinorVersion = BigInteger.ValueOf(1L).ToString(),
        AP_Info = apInfo,
        MSSP_Info = messageAbstractTypeMSSP_Info,
        MobileUser = mobileUser,
    };


    var resp = await client.MSS_RegistrationAsync(request);

    Console.WriteLine($"Response Status: {resp.MSS_RegistrationResp.Status.StatusCode.Value.ToString()}");


    if (resp.MSS_RegistrationResp.Status.StatusCode.Value == "408")
    {
        ServiceReference.CertificateResponse[] certResp = resp.MSS_RegistrationResp.CertificateResponse;

        X509Certificate2 __cert = X509CertificateLoader.LoadCertificate(certResp[0].X509Certificate);
        Console.WriteLine($"Certificate: {__cert.Subject}");
    }
}

static async Task TestSign()
{
    // Example of loading a certificate from a file
    var cert = X509CertificateLoader.LoadPkcs12FromFile(
        "D:\\projects\\vgca\\MPKIToolKit\\Deploy\\mpkicrypto-v1.0.16-24.07.2023\\cert-ap-test\\3108937_VGCA_Application_Provider_certificate.p12",
        "123456"
    );
    Console.WriteLine($"Loaded certificate with thumbprint: {cert.Thumbprint}");


    String ApId = "http://ap.mobile-id.vn/viettelca";        // Replace with your actual AP_ID
    String ApPassword = "5Ge2GSA3";   // Replace with your actual AP_PWD

    String msspId = "http://hmssp.mobile-id.vn"; // Replace with your actual MSSP_ID

    String phoneNumber = "84962594424"; // Replace with actual phone number

    byte[] message = Encoding.UTF8.GetBytes("1234567890");
    string hashAlgorithm = "SHA256";


    String dataToBeDisplayed = "Hello, this is a test signature request!";
    String signatureProfile = "http://mobile-id.vn/digitalSignature";
    String mss_format = "http://uri.etsi.org/TS102204/v1.1.2#PKCS1";

    ServiceReference.MSS_SignatureTypeClient client = new ServiceReference.MSS_SignatureTypeClient();
    client.ClientCredentials.Windows.ClientCredential = System.Net.CredentialCache.DefaultNetworkCredentials;
    client.ChannelFactory.Credentials.ServiceCertificate.SslCertificateAuthentication =
    client.ClientCredentials.ServiceCertificate.SslCertificateAuthentication =
    new X509ServiceCertificateAuthentication
    {
        CertificateValidationMode = X509CertificateValidationMode.None,
        RevocationMode = X509RevocationMode.NoCheck,
    };
    client.ClientCredentials.ClientCertificate.Certificate = cert;
    client.ChannelFactory.Credentials.ClientCertificate.Certificate = cert;

    MessagingModeType messagingMode = MessagingModeType.synch;

    MSS_SignatureReqType sigReq = new MSS_SignatureReqType();

    sigReq.MajorVersion = BigInteger.ValueOf(1L).ToString();
    sigReq.MinorVersion = BigInteger.ValueOf(1L).ToString();

    MessageAbstractTypeAP_Info aiObject = new MessageAbstractTypeAP_Info();
    aiObject.AP_ID = ApId;
    aiObject.AP_PWD = ApPassword;

    aiObject.AP_TransID = Guid.NewGuid().ToString("N").Substring(0, 10);
    aiObject.Instant = DateTime.Now;
    sigReq.AP_Info = aiObject;

    MessageAbstractTypeMSSP_Info miObject = new MessageAbstractTypeMSSP_Info();
    MeshMemberType _msspId = new MeshMemberType();
    _msspId.URI = msspId;
    miObject.MSSP_ID = _msspId;
    sigReq.MSSP_Info = miObject;

    MobileUserType muObject = new MobileUserType();
    muObject.MSISDN = phoneNumber;
    sigReq.MobileUser = muObject;

    AlgorithmIdentifier algId = new AlgorithmIdentifier(DigestUtilities.GetObjectIdentifier(hashAlgorithm), DerNull.Instance);
    IDigest digest = DigestUtilities.GetDigest(hashAlgorithm);
    byte[] hash = new byte[digest.GetDigestSize()];
    digest.BlockUpdate(message, 0, message.Length);
    digest.DoFinal(hash, 0);

    DigestInfo dInfo = new DigestInfo(algId, hash);
    byte[] hashedstr = dInfo.GetDerEncoded();

    DataType dsObject = new DataType();
    dsObject.MimeType = "application/octet-stream";
    dsObject.Encoding = "base64";
    dsObject.Value = Convert.ToBase64String(hashedstr);
    sigReq.DataToBeSigned = dsObject;

    if (dataToBeDisplayed != null)
    {
        DataType ddObject = new DataType();
        ddObject.MimeType = "text/plain";
        ddObject.Encoding = "UTF-8";
        ddObject.Value = dataToBeDisplayed;

        sigReq.DataToBeDisplayed = ddObject;
    }

    mssURIType spObject = new mssURIType();
    spObject.mssURI = new Uri(signatureProfile).ToString();
    sigReq.SignatureProfile = spObject;

    if (mss_format != null)
    {
        mssURIType mfObject = new mssURIType();
        mfObject.mssURI = new Uri(mss_format).ToString();
        sigReq.MSS_Format = mfObject;
    }

    sigReq.MessagingMode = messagingMode;
    sigReq.AdditionalServices = new AdditionalServiceType[] {
        new AdditionalServiceType()
        {
            Description = new mssURIType()
            {
                mssURI = "http://mobile-id.vn/MSSP/v1.0.0#signingCertificate"
            }
        },
        new AdditionalServiceType()
        {
            Description = new mssURIType()
            {
                mssURI = "http://mobile-id.vn/MSSP/v1.0.0#signatureValidation"
            }
        }
    };
    sigReq.TimeOut = "300";

    var sigResp = await client.MSS_SignatureAsync(sigReq);
    Console.WriteLine($"Response Status: {sigResp.MSS_SignatureResp.Status.StatusCode.Value.ToString()}");

    if (sigResp.MSS_SignatureResp.Status.StatusCode.Value == "408")
    {
        byte[] sigBuff = sigResp.MSS_SignatureResp.MSS_Signature.Item;

        Console.WriteLine($"Signature: {Convert.ToBase64String(sigBuff)}");
    }

}

await TestGetCertAsync();

await TestSign();


