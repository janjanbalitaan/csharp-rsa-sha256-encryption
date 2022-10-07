using System;
using System.IO;
using System.Security.Cryptography;

class CSEncryption{

    static void Main() {
        try{
            string textToEncrypt = "encrypted text";
            byte[] bytesTextToEncrypt = System.Text.Encoding.UTF8.GetBytes(textToEncrypt);
            RSAEncryptionPadding rep = RSAEncryptionPadding.OaepSHA256;
            string existingPrivPem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA5zXdG2V4uW7xsakkT9UISbOQ9D2Zn4iRZJQHfjp1Lfezyn8b\nBw0OHopXA7T5G6cF5FiaOjzGIJLT/bnkrd1324O4LaQueACLTlP+UkueRJs6Yl2M\nDNV0bF8X6tYt/Eo/wAnln/EBRcwfAGArFJeo/jbnlevehboyzb7kV+uL4HdC9NJU\nRUcv1xcCjW3yVU9u5Aq4AZjO7d1Jx8WbifDF0V+LkXF08qZUfZkuvBIxwwOwNTeD\na+GH1mnUiq78ft6u0sG8SU4aM3KXIE6RjUYQTyheAFZ2JaKOxtYw4lYQQFyvAKFf\nmf7wrud7UmlCSfdet5jNtOb7H7IB0XtplVN88wIDAQABAoIBAGZd2r8+dezjye62\nzHTsBPdcoVkBzPptJLI7N/YTO75WZSvKitTcWtv6s/vYLFKp6FnpQJ94OOBDIci8\nfRrdayutbeYHQuuukf7kAT2+bRxC/d5/PHqSJzG0CIrYuRNybDdCKoBd3ApjDXbF\nHU3It/GVrYMbIzJh9gxR8BddGlkOnQRPc/hEUkD+G2bAiNRMq8TtReV5IezBLesw\ntGLlVLa27pu2/PawJ7kD7Zw0f/9TatncY/w9POvs6aOe3O1Ft4CWmLJw9ZZUsp8g\nQoPi6b7dgiCR0YKk0txuPHNTHtkB1I6oQqVvccYcm7WGz9Dvt35ZG6nEIpM7WWa+\nVmzcsEECgYEA+Es3IRmQcG8gLdrIyaKQlqyzNSquKQ3+IIy3qVp8k/s/0fWpku80\nhXgNSqnOL8YumoxlIlJeMqRHYL9uV0CGeJVY9kZ/qNJrjF9qWKjAtk+EAyvZoRfa\n0zKIdR8UOOlV4uoOqFTXKZbnFv+e2xucPtDPisD5jHjh+kuG+A5TpncCgYEA7mLq\nG5lTInS8fdbjsramSBL7qMnMBVHVd7/mxuMRvJB/hzCWnF6pXttgfskNw49CZYLt\nFATSX8XYkyCm6eISJxRrBVBKYlny/QbiFx41eVI6r2dnbXiVyGoD975R/DfAuyTt\n5WFeoG+/uRLAMTAx+L7m9W3A21pkEasnW55nsGUCgYEA1S9PgF4AxGjFilmFeIrZ\n9mUF4appqtpWzf/EWeZVfIGHRHDXTk+QGuD/GJI/dImGzi+pThTGyFiA6LK0vLms\nO7CPl7TkO0GgEgCCwOjzvhT71fU6gLSIsDl9LIKozEyb757jQujFbPIiLH8CGELW\nnqCO8iXKni/UZyGeGzHB5PUCgYAI4uENNFL4Btf77OXCBLMAHs0IxrT3QcyuURX+\nNfq0R8KpPHNw0sqHgbAAKeh8cLut4wqJY4CgF1TybxYpw8afdFBk+1A6iFXZfscw\ny2x84EbVwQoG96bFuMX7FzohJ8bkcwT3NwD7BA9mi79kVgKW3i7n2TaGNsFiMzod\nXTNKTQKBgQDgTa+uVgu96Cyk+CyOlqM031T8nByjEPkawiRGftBwwh9/FKri8Wf9\n8W+3F9acwb2VmwNJrn7cn41NNgiqMJD6+vwobn8xGe8zplREjxzSfBVwDvuw0mDl\n5LgAWRDLEqeTXDSUzy8p91j+mVG1uDzkvWgQmqHIw0sM6yuEg2nzBg==\n-----END RSA PRIVATE KEY-----";
            // reference to create from scratch
            RunNew(bytesTextToEncrypt, rep);
            // reference to create with existing private key
            RunWithPrivateKey(existingPrivPem, bytesTextToEncrypt, rep);
            // reference to encrypt string and decrypt on other platform
            RunEncryptWithPrivateKey(existingPrivPem, System.Text.Encoding.UTF8.GetBytes("Decrypt in Python"), rep);
            // base64 encoded string to decrypt
            byte[] bytesTextToDecrypt = Convert.FromBase64String("j9WLiDbxeEIph1oMApRfZvv+cQjumAzzfBFgRJYqxVrqm1WIDvXJSD84pmDNU8aX4IRbx9cH7yqyxLeuB4fpQyuQYCrLTMrBF8GvToaLG1M4jcjWNS0CO224o28FuoxJhTw+dDDBDgCNIHfnCA9wpqzj2AS/9gU2XksHmV5Rl+t96XU2AKi581jz/N4JnS1RjqHnebL4tCkVesBUHpQSGYKBmebChCONej/JgMiN16xCAiIbhXIh0wCzLmXixCB/UOC5FKVLb44vaQ6HRjFQBrnu5O6KKGTO2aWOrh3jMqshs7yrn7uNei9PH44Cg5EkD7RYjrBRte7LVPp6BfVd+w==");
            RunDecryptWithPrivateKey(existingPrivPem, bytesTextToDecrypt, rep);
        }catch(ArgumentNullException){
            Console.WriteLine("Exception");
        }
    }

    public static void RunNew(
        byte[] bytesTextToEncrypt,
        RSAEncryptionPadding rep
    ) {
        Console.WriteLine("----------Running: RunNew()----------");
        // Create a new private and public key
        RSA r = GenerateRSA(2048);
        byte[] rPriv = GetPrivateKey(r);
        byte[] rPub = GetPublicKey(r);
        string rPrivPem = GeneratePEMString(rPriv, "private");
        string rPubPem = GeneratePEMString(rPub, "public");
        Console.WriteLine("Private Key:");
        Console.WriteLine(rPrivPem);
        Console.WriteLine("Public Key:");
        Console.WriteLine(rPubPem);
        byte[] encryptedText = EncryptBytes(r, bytesTextToEncrypt, rep);
        Console.WriteLine($"Encrypted Text: {Convert.ToBase64String(encryptedText)}");
        byte[] decryptedText = DecryptBytes(r, encryptedText, rep);
        Console.WriteLine($"Decrypted Text: {System.Text.Encoding.UTF8.GetString(decryptedText)}");
        Console.WriteLine("----------Finished: RunNew()----------");
    }

    public static void RunWithPrivateKey(
        string existingPrivPem,
        byte[] bytesTextToEncrypt,
        RSAEncryptionPadding rep
    ) {
        Console.WriteLine("----------Running: RunWithPrivateKey()----------");
        RSA newR = GenerateRSAFromPrivateKeyPem(existingPrivPem); 
        byte[] encryptedText = EncryptBytes(newR, bytesTextToEncrypt, rep);
        Console.WriteLine($"Encrypted Text: {Convert.ToBase64String(encryptedText)}");
        // Decryption
        byte[] decryptedText = DecryptBytes(newR, encryptedText, rep);
        Console.WriteLine($"Decrypted Text: {System.Text.Encoding.UTF8.GetString(decryptedText)}");
        Console.WriteLine("----------Finished: RunWithPrivateKey()----------");
    }

    public static void RunEncryptWithPrivateKey(
        string existingPrivPem,
        byte[] bytesTextToEncrypt,
        RSAEncryptionPadding rep
    ) {
        Console.WriteLine("----------Running: RunEncryptWithPrivateKey()----------");
        RSA newR = GenerateRSAFromPrivateKeyPem(existingPrivPem); 
        byte[] encryptedText = EncryptBytes(newR, bytesTextToEncrypt, rep);
        Console.WriteLine($"Encrypted Text: {Convert.ToBase64String(encryptedText)}");
        Console.WriteLine("----------Finished: RunEncryptWithPrivateKey()----------");
    }

    public static void RunDecryptWithPrivateKey(
        string existingPrivPem,
        byte[] bytesTextToDecrypt,
        RSAEncryptionPadding rep
    ) {
        Console.WriteLine("----------Running: RunDecryptWithPrivateKey()----------");
        // Use existing private key
        RSA newR = GenerateRSAFromPrivateKeyPem(existingPrivPem); 
        // Decryption
        byte[] decryptedText = DecryptBytes(newR, bytesTextToDecrypt, rep);
        Console.WriteLine($"Decrypted Text: {System.Text.Encoding.UTF8.GetString(decryptedText)}");
        Console.WriteLine("----------Finished: RunDecryptWithPrivateKey()----------");
    }

    public static RSA GenerateRSA(
        object? param = null
    ){
        RSA rsa;
        if(param != null){
            if(param is RSAParameters) {
                rsa = RSA.Create((RSAParameters) param);
            }else if(param is int) {
                rsa = RSA.Create((int) param);
            }/** TODO: else if(param is string) {
                rsa = RSA.Create(param.ToString());
            }**/else{
                rsa = RSA.Create();
            }
        } else {
            rsa = RSA.Create();
        }
         
        return rsa;
    }

    public static RSA GenerateRSAFromPrivateKeyPem(
        string privateKeyPem
    ){
        RSA rsa = RSA.Create();
        string privateKey = privateKeyPem.Replace("-----BEGIN RSA PRIVATE KEY-----", "");
        privateKey = privateKey.Replace("\n", "");
        privateKey = privateKey.Replace("-----END RSA PRIVATE KEY-----", "");
        byte[] privateKeyBytes = Convert.FromBase64String(privateKey);
        rsa.ImportRSAPrivateKey(privateKeyBytes, out _);
        return rsa;
    }

    public static string GeneratePublicAndPrivateKeyXMLString(
        RSA rsa
    ){
        return rsa.ToXmlString(true);
    }

    public static byte[] GetPrivateKey(
        RSA rsa
    ){
        return rsa.ExportRSAPrivateKey();
    }

    public static byte[] GetPublicKey(
        RSA rsa
    ){
        return rsa.ExportSubjectPublicKeyInfo();
    }

    public static string GeneratePEMString(
        byte[] key,
        string type = "public"
    ){
        string header = "-----BEGIN PUBLIC KEY-----";
        string footer = "-----END PUBLIC KEY-----";
        if(type == "private") {
            header = "-----BEGIN RSA PRIVATE KEY-----";
            footer = "-----END RSA PRIVATE KEY-----";
        }

        string keyString = FormatToPEM(Convert.ToBase64String(key));
        return $"{header}\n{keyString}\n{footer}";
    }

    public static string FormatToPEM(
        string text
    ){
        string newText = "";
        for (int i = 0; i < text.Length; i += 64){
            int start = i;
            int end = 64;
            string p = "\n";
            if(end + start > text.Length){
                end = text.Length - start;
                p = "";
            }
            
            newText = newText + text.Substring(start, end) + p;
        }

        return newText;
    }

    public static byte[] EncryptBytes(
        RSA rsa,
        byte[] byteData,
        RSAEncryptionPadding rep 
    ){
        return rsa.Encrypt(byteData, rep);
    }

    public static byte[] DecryptBytes(
        RSA rsa,
        byte[] byteData,
        RSAEncryptionPadding rep 
    ){
        return rsa.Decrypt(byteData, rep);
    }
}
