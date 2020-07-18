//
//  Copyright (c) 2012-2019  Finnbarr P. Murphy.  All rights reserved.
//
//  Display UEFI Secure Boot keys and certificates (PK, KEK, db, dbx)
// 
//  License: BSD 2 clause License
//

#include "UefiBaseType.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "GlobalVariable.h"
#include "WinCertificate.h"
#include "ImageAuthentication.h"
#include "oid_registry.h"
#include "x509.h"
#include "asn1_ber_decoder.h"

#define UTCDATE_LEN 23
#define UTILITY_VERSION "20190403"
#undef DEBUG

// temporary store for output text
CHAR16 tmpbuf[1000];
int    wrapno = 1;

rsize_t strlen_s(char* str)
{
    return (rsize_t)(strlen(str) * 2);
}

int CompareGuid(GUID *first, GUID *second)
{
    int mismatchIndex = 0;
    for (int i = 0; i < 8; i++)
    {
        if (first->Data4[i] != second->Data4[i])
        {
            mismatchIndex = i + 1;
            break;
        }
    }

    return mismatchIndex;
}

void GetCertType(GUID* certGUID, char** typeName)
{
    EFI_GUID gX509 = EFI_CERT_X509_GUID;
    EFI_GUID gPKCS7 = EFI_CERT_TYPE_PKCS7_GUID;
    EFI_GUID gRSA2048 = EFI_CERT_RSA2048_GUID;
    EFI_GUID gSHA256 = EFI_CERT_SHA256_GUID;
    EFI_GUID gRSA2048SHA256 = EFI_CERT_RSA2048_SHA256_GUID;
    EFI_GUID gSHA1 = EFI_CERT_SHA1_GUID;
    EFI_GUID gRSA2048SHA1 = EFI_CERT_RSA2048_SHA1_GUID;
    EFI_GUID gSHA224 = EFI_CERT_SHA224_GUID;
    EFI_GUID gSHA384 = EFI_CERT_SHA384_GUID;
    EFI_GUID gSHA512 = EFI_CERT_SHA512_GUID;
    EFI_GUID gX509SHA256 = EFI_CERT_X509_SHA256_GUID;
    EFI_GUID gX509SHA384 = EFI_CERT_X509_SHA384_GUID;
    EFI_GUID gX509SHA512 = EFI_CERT_X509_SHA512_GUID;

    if (CompareGuid(certGUID, &gX509) == 0)
        strcpy_s(*typeName, strlen("X509") + 1, "X509");
    else if (CompareGuid(certGUID, &gPKCS7) == 0)
        strcpy_s(*typeName, strlen("PKCS7") + 1, "PKCS7");
    else if (CompareGuid(certGUID, &gRSA2048) == 0)
        strcpy_s(*typeName, strlen("RSA2048") + 1, "RSA2048");
    else if (CompareGuid(certGUID, &gSHA256) == 0)
        strcpy_s(*typeName, strlen("SHA256") + 1, "SHA256");
    else if (CompareGuid(certGUID, &gRSA2048SHA256) == 0)
        strcpy_s(*typeName, strlen("RSA2048SHA256") + 1, "RSA2048SHA256");
    else if (CompareGuid(certGUID, &gSHA1) == 0)
        strcpy_s(*typeName, strlen("SHA1") + 1, "SHA1");
    else if (CompareGuid(certGUID, &gRSA2048SHA1) == 0)
        strcpy_s(*typeName, strlen("RSA2048SHA1") + 1, "RSA2048SHA1");
    else if (CompareGuid(certGUID, &gSHA224) == 0)
        strcpy_s(*typeName, strlen("SHA224") + 1, "SHA224");
    else if (CompareGuid(certGUID, &gSHA384) == 0)
        strcpy_s(*typeName, strlen("SHA384") + 1, "SHA384");
    else if (CompareGuid(certGUID, &gSHA512) == 0)
        strcpy_s(*typeName, strlen("SHA512") + 1, "SHA512");
    else if (CompareGuid(certGUID, &gX509SHA256) == 0)
        strcpy_s(*typeName, strlen("X509SHA256") + 1, "X509SHA256");
    else if (CompareGuid(certGUID, &gX509SHA384) == 0)
        strcpy_s(*typeName, strlen("X509SHA384") + 1, "X509SHA384");
    else if (CompareGuid(certGUID, &gX509SHA512) == 0)
        strcpy_s(*typeName, strlen("X509SHA512") + 1, "X509SHA512");
    else
        strcpy_s(*typeName,strlen("UNKNOWN") + 1,"UNKNOWN");
}

CHAR16 *
AsciiToUnicode( const char *Str, 
                int Len )
{
    CHAR16 *Ret = calloc(Len * 2 + 2, sizeof(char));

    if (!Ret)
        return NULL;

    for (int i = 0; i < Len; i++)
        Ret[i] = Str[i];

    return Ret;
}


int 
do_version( void *context, 
            long state_index,
            unsigned char tag,
            const void *value, 
            long vlen )
{
    int Version = *(const char *)value;

    printf("  Version: %d (0x%02x) ", Version + 1, Version);

    return 0;
}


int
do_signature( void *context, 
              long state_index,
              unsigned char tag,
              const void *value,
              long vlen )
{
    printf("  Signature Algorithm: %s\n", tmpbuf);
    tmpbuf[0] = '\0';

    return 0;
}


int
do_algorithm( void *context,
              long state_index,
              unsigned char tag,
              const void *value, 
              long vlen )
{
    enum OID oid; 
    CHAR16 buffer[100];

    oid = Lookup_OID(value, vlen);
    Sprint_OID(value, vlen, buffer, sizeof(buffer));
    if (oid == OID_id_dsa_with_sha1)
        strcpy_s(tmpbuf, strlen_s("id_dsa_with_sha1"), "id_dsa_with_sha1");
    else if (oid == OID_id_dsa)
        strcpy_s(tmpbuf, strlen_s("id_dsa"), "id_dsa");
    else if (oid == OID_id_ecdsa_with_sha1)
        strcpy_s(tmpbuf, strlen_s("id_ecdsa_with_sha1"), "id_ecdsa_with_sha1");
    else if (oid == OID_id_ecPublicKey)
        strcpy_s(tmpbuf, strlen_s("id_ecPublicKey"), "id_ecPublicKey");
    else if (oid == OID_rsaEncryption)
        strcpy_s(tmpbuf, strlen_s("rsaEncryption"), "rsaEncryption");
    else if (oid == OID_md2WithRSAEncryption)
        strcpy_s(tmpbuf, strlen_s("md2WithRSAEncryption"), "md2WithRSAEncryption");
    else if (oid == OID_md3WithRSAEncryption)
        strcpy_s(tmpbuf, strlen_s("md3WithRSAEncryption"), "md3WithRSAEncryption");
    else if (oid == OID_md4WithRSAEncryption)
        strcpy_s(tmpbuf, strlen_s("md4WithRSAEncryption"), "md4WithRSAEncryption");
    else if (oid == OID_sha1WithRSAEncryption)
        strcpy_s(tmpbuf, strlen_s("sha1WithRSAEncryption"), "sha1WithRSAEncryption");
    else if (oid == OID_sha256WithRSAEncryption)
        strcpy_s(tmpbuf, strlen_s("sha256WithRSAEncryption"), "sha256WithRSAEncryption");
    else if (oid == OID_sha384WithRSAEncryption)
        strcpy_s(tmpbuf, strlen_s("sha384WithRSAEncryption"), "sha384WithRSAEncryption");
    else if (oid == OID_sha512WithRSAEncryption)
        strcpy_s(tmpbuf, strlen_s("sha512WithRSAEncryption"), "sha512WithRSAEncryption");
    else if (oid == OID_sha224WithRSAEncryption)
        strcpy_s(tmpbuf, strlen_s("sha224WithRSAEncryption"), "sha224WithRSAEncryption");
    else {
        strcat_s(tmpbuf,strlen_s(" ("), " (");
        strcat_s(tmpbuf,strlen_s(buffer), buffer);
        strcat_s(tmpbuf,strlen_s(")"), ")");
    }

    return 0;
}


int 
do_serialnumber( void *context, 
                 long state_index,
                 unsigned char tag,
                 const void *value, 
                 long vlen )
{
    char *p = (char *)value;

    printf("  Serial Number: ");
    if (vlen > 4) {
        for (int i = 0; i < vlen; i++, p++) {
            printf("%02x%c", (UINT8)*p, ((i+1 == vlen)?' ':':'));
        }
    }
    printf("\n");

    return 0;
}


int
do_issuer( void *context,
           long  state_index,
           unsigned char tag,
           const void *value,
           long vlen )
{
    wprintf("  Issuer:%ls\n", tmpbuf);
    tmpbuf[0] = '\0';

    return 0;
}


int
do_subject( void *context,
            long state_index,
            unsigned char tag,
            const void *value,
            long vlen )
{
    printf("  Subject:%ls\n", tmpbuf);
    tmpbuf[0] = '\0';

    return 0;
}


int
do_attribute_type( void *context,
                   long state_index,
                   unsigned char tag,
                   const void *value,
                   long vlen )
{
    enum OID oid; 
    CHAR16 buffer[60];

    oid = Lookup_OID(value, vlen);
    Sprint_OID(value, vlen, buffer, sizeof(buffer));
   
    if (oid == OID_countryName) {
        strcat_s(tmpbuf,strlen_s(" C="), " C=");
    } else if (oid == OID_stateOrProvinceName) {
        strcat_s(tmpbuf,strlen_s(" ST="), " ST=");
    } else if (oid == OID_locality) {
        strcat_s(tmpbuf,strlen_s(" L="), " L=");
    } else if (oid == OID_organizationName) {
        strcat_s(tmpbuf,strlen_s(" O="), " O=");
    } else if (oid == OID_commonName) {
        strcat_s(tmpbuf,strlen_s(" CN="), " CN=");
    } else {
        strcat_s(tmpbuf,strlen_s(" ("), " (");
        strcat_s(tmpbuf,strlen_s(buffer), buffer);
        strcat_s(tmpbuf,strlen_s(")"), ")");
    }

    return 0;
}


int
do_attribute_value( void *context,
                    long state_index,
                    unsigned char tag,
                    const void *value,
                    long vlen )
{
    CHAR16 *ptr;

    ptr = AsciiToUnicode(value, (int)vlen);
    strcat_s(tmpbuf, strlen_s(ptr),ptr);
    free(ptr);

    return 0;
}


int
do_extensions( void *context,
               long state_index,
               unsigned char tag,
               const void *value,
               long vlen )
{
    wprintf("  Extensions:%ls\n", tmpbuf);
    tmpbuf[0] = '\0';
    wrapno = 1;

    return 0;
}


int
do_extension_id( void *context, 
                 long state_index,
                 unsigned char tag,
                 const void *value,
                 long vlen )
{
    enum OID oid; 
    CHAR16 buffer[60];
    int len = strlen_s(tmpbuf);

    if (len > (90*wrapno)) {
        // Not sure why a CR is now required in UDK2017.  Need to investigate
        strcat_s(tmpbuf, strlen_s("\r\n             "),"\r\n             ");
        wrapno++;
    }

    oid = Lookup_OID(value, vlen);
    Sprint_OID(value, vlen, buffer, sizeof(buffer));

    if (oid == OID_subjectKeyIdentifier)
        strcat_s(tmpbuf, strlen_s(" SubjectKeyIdentifier")," SubjectKeyIdentifier");
    else if (oid == OID_keyUsage)
        strcat_s(tmpbuf, strlen_s(" KeyUsage")," KeyUsage");
    else if (oid == OID_subjectAltName)
        strcat_s(tmpbuf, strlen_s(" SubjectAltName")," SubjectAltName");
    else if (oid == OID_issuerAltName)
        strcat_s(tmpbuf, strlen_s(" IssuerAltName")," IssuerAltName");
    else if (oid == OID_basicConstraints)
        strcat_s(tmpbuf, strlen_s(" BasicConstraints")," BasicConstraints");
    else if (oid == OID_crlDistributionPoints)
        strcat_s(tmpbuf, strlen_s(" CrlDistributionPoints")," CrlDistributionPoints");
    else if (oid == OID_certAuthInfoAccess) 
        strcat_s(tmpbuf, strlen_s(" CertAuthInfoAccess")," CertAuthInfoAccess");
    else if (oid == OID_certPolicies)
        strcat_s(tmpbuf, strlen_s(" CertPolicies")," CertPolicies");
    else if (oid == OID_authorityKeyIdentifier)
        strcat_s(tmpbuf, strlen_s(" AuthorityKeyIdentifier")," AuthorityKeyIdentifier");
    else if (oid == OID_extKeyUsage)
        strcat_s(tmpbuf, strlen_s(" ExtKeyUsage")," ExtKeyUsage");
    else if (oid == OID_msEnrollCerttypeExtension)
        strcat_s(tmpbuf, strlen_s(" msEnrollCertTypeExtension")," msEnrollCertTypeExtension");
    else if (oid == OID_msCertsrvCAVersion)
        strcat_s(tmpbuf, strlen_s(" msCertsrvCAVersion")," msCertsrvCAVersion");
    else if (oid == OID_msCertsrvPreviousCertHash)
        strcat_s(tmpbuf, strlen_s(" msCertsrvPreviousCertHash")," msCertsrvPreviousCertHash");
    else {
        strcat_s(tmpbuf,strlen_s(" ("), " (");
        strcat_s(tmpbuf,strlen_s(buffer), buffer);
        strcat_s(tmpbuf,strlen_s(")"), ")");
    }

    return 0;
}


//
//  Yes, a hack but it works!
//
char *
make_utc_date_string( char *s )
{
    static char buffer[50];
    char  *d;

    d = buffer;
    *d++ = '2';      /* year */
    *d++ = '0';
    *d++ = *s++;
    *d++ = *s++;
    *d++ = '-';
    *d++ = *s++;     /* month */
    *d++ = *s++;
    *d++ = '-';
    *d++ = *s++;     /* day */
    *d++ = *s++;
    *d++ = ' ';
    *d++ = *s++;     /* hour */
    *d++ = *s++;
    *d++ = ':';
    *d++ = *s++;     /* minute */
    *d++ = *s++;
    *d++ = ':';
    *d++ = *s++;     /* second */
    *d++ = *s;
    *d++ = ' ';
    *d++ = 'U';
    *d++ = 'T';
    *d++ = 'C';
    *d = '\0';

    return buffer;
}


int
do_validity_not_before( void *context,
                        long state_index,
                        unsigned char tag,
                        const void *value, 
                        long vlen )
{
    CHAR16 *ptr;
    char *p;

    p = make_utc_date_string((char *)value);
    ptr = AsciiToUnicode(p, UTCDATE_LEN);
    wprintf("  Validity:  Not Before: %ls", ptr);
    free(ptr);

    return 0;
}


int
do_validity_not_after( void *context,
                       long state_index,
                       unsigned char tag,
                       const void *value,
                       long vlen )
{
    CHAR16 *ptr;
    char *p;

    p = make_utc_date_string((char *)value);
    ptr = AsciiToUnicode(p, UTCDATE_LEN);
    wprintf("   Not After: %ls\n", ptr);
    free(ptr);

    return 0;
}


int
do_subject_public_key_info( void *context, 
                            long state_index,
                            unsigned char tag,
                            const void *value, 
                            long vlen )
{
    wprintf("  Subject Public Key Algorithm: %ls\n", tmpbuf);
    tmpbuf[0] = '\0';

    return 0;
}

/*
int
PrintCertificates( UINT8 *data, 
                   UINTN len, 
                   FILE *fp )
{
    EFI_SIGNATURE_LIST *CertList = (EFI_SIGNATURE_LIST *)data;
    EFI_SIGNATURE_DATA *Cert;
    EFI_GUID gX509 = EFI_CERT_X509_GUID;
    EFI_GUID gPKCS7 = EFI_CERT_TYPE_PKCS7_GUID;
    EFI_GUID gRSA2048 = EFI_CERT_RSA2048_GUID;
    BOOLEAN  CertFound = FALSE;
    CHAR16   *ext;
    UINTN    DataSize = len;
    UINTN    CertCount = 0;
    UINTN    buflen;
    int      status = 0;

    while ((DataSize > 0) && (DataSize >= CertList->SignatureListSize)) {
        CertCount = (CertList->SignatureListSize - CertList->SignatureHeaderSize) / CertList->SignatureSize;
        Cert = (EFI_SIGNATURE_DATA *) ((UINT8 *) CertList + sizeof (EFI_SIGNATURE_LIST) + CertList->SignatureHeaderSize);

        // should all be X509 but just in case...
        if (CompareGuid(&CertList->SignatureType, &gX509) == 0)
            ext = L"X509";
        else if (CompareGuid(&CertList->SignatureType, &gPKCS7) == 0)
            ext = L"PKCS7";
        else if (CompareGuid(&CertList->SignatureType, &gRSA2048) == 0)
            ext = L"RSA2048";
        else 
            ext = L"Unknown";

        for (UINTN Index = 0; Index < CertCount; Index++) {
            if ( CertList->SignatureSize > 100 ) {
                CertFound = TRUE;
                Print(L"\nType: %s  (GUID: %g)\n", ext, &Cert->SignatureOwner);
                buflen  = CertList->SignatureSize-sizeof(EFI_GUID);
                status = asn1_ber_decoder(&x509_decoder, NULL, Cert->SignatureData, buflen);
            }
            Cert = (EFI_SIGNATURE_DATA *) ((UINT8 *) Cert + CertList->SignatureSize);
        }
        DataSize -= CertList->SignatureListSize;
        CertList = (EFI_SIGNATURE_LIST *) ((UINT8 *) CertList + CertList->SignatureListSize);
    }

    if ( CertFound == FALSE ) {
       Print(L"\nNo certificates found for this database\n");
    }

    return status;
}
*/
int
PrintCertificates( UINT8 *data, 
                   UINTN len, 
                   FILE **fp )
{
    fread_s(data,8000, sizeof(char), len, *fp);
	
    EFI_SIGNATURE_LIST *CertList = (EFI_SIGNATURE_LIST *)data;
    EFI_SIGNATURE_DATA *Cert;
    char* certType = calloc(50, sizeof(char));
    BOOLEAN  CertFound = FALSE;
    UINTN    DataSize = len;
    UINTN    CertCount = 0;
    UINTN    buflen;
    int      status = 0;
	
	

    while ((DataSize > 0) && (DataSize >= CertList->SignatureListSize)) {
        CertCount = (CertList->SignatureListSize - CertList->SignatureHeaderSize) / CertList->SignatureSize;
        Cert = (EFI_SIGNATURE_DATA *) ((UINT8 *) CertList + sizeof (EFI_SIGNATURE_LIST) + CertList->SignatureHeaderSize);

        memset(certType, 0, 50);

        // should all be X509 but just in case...
        GetCertType(&(CertList->SignatureType), &certType);
        
        for (UINTN Index = 0; Index < CertCount; Index++) {
            if ( CertList->SignatureSize > 100 ) {
                CertFound = TRUE;
                printf("\nType: %s  (GUID: %g)\n", certType, &Cert->SignatureOwner);
                buflen  = CertList->SignatureSize-sizeof(EFI_GUID);
                status = asn1_ber_decoder(&x509_decoder, NULL, Cert->SignatureData, buflen);
            }
            Cert = (EFI_SIGNATURE_DATA *) ((UINT8 *) Cert + CertList->SignatureSize);
        }
        DataSize -= CertList->SignatureListSize;
        CertList = (EFI_SIGNATURE_LIST *) ((UINT8 *) CertList + CertList->SignatureListSize);
    }

    if ( CertFound == FALSE ) {
       printf("\nNo certificates found for this database\n");
    }
    free(certType);

    return status;
}

/*
EFI_STATUS
get_variable( CHAR16 *Var, 
              UINT8 **Data, 
              UINTN *Len,
              EFI_GUID Owner )
{
    EFI_STATUS Status;

    *Len = 0;
	
	
	
	
    Status = gRT->GetVariable( Var, &Owner, NULL, Len, NULL );
    if (Status != EFI_BUFFER_TOO_SMALL)
        return Status;

    *Data = AllocateZeroPool( *Len );
    if (!Data)
        return EFI_OUT_OF_RESOURCES;
    
    Status = gRT->GetVariable( Var, &Owner, NULL, Len, *Data );
    if (Status != EFI_SUCCESS) {
        FreePool( *Data );
        *Data = NULL;
    }

    return Status;
}
*/
EFI_STATUS
get_variable( char *filename, 
              UINT8 *Data, 
              UINTN *Len,
              FILE **fp )
{
    EFI_STATUS Status = EFI_SUCCESS;

    int err = 0;
    *Len = 0;
    printf("Prepping to open file %s\n",filename);
    err = fopen_s(fp, filename, "rb");
        
    if (err == 0)
    {
        while (fgetc(*fp) != EOF)
        {
            *Len = *Len + 1;
        }
        fclose(*fp);
        fopen_s(fp, filename, "rb");

        printf("Success Opening\n");
        Status = EFI_SUCCESS;
    }
    else
    {
        printf("Error Opening\n");
        Status = EFI_LOAD_ERROR;
    }

    return Status;
}

EFI_STATUS
OutputVariable( char *Var, 
                EFI_GUID Owner,
				char *filepath
				) 
{
    EFI_STATUS Status = EFI_SUCCESS;
    UINT8 *Data = calloc(8000,sizeof(char)); //TODO: hardcoding because I just want to process the DBX update for now
    UINTN Len = 8000;
    FILE *fp = calloc(1, sizeof(FILE));

    printf("Prepping to get data\n");
    
    Status = get_variable( filepath, Data, &Len, &fp );
    if (Status == EFI_SUCCESS) {
        printf("\nFILEPATH: %s  (pointer: %p)\n", filepath, &fp);
        PrintCertificates( Data, Len, &fp );
        
    } else if (Status == EFI_NOT_FOUND) {
        printf("Variable %s not found\n", Var);
        return Status;
    }
    else
    {
        printf("ERROR: Failed to get variable %s. Status Code: %d\n", Var, Status);
    }
	free( Data );

    fclose(fp);

    return Status;
}


VOID
Usage( BOOLEAN ErrorMsg )
{
    if ( ErrorMsg ) {
        printf("ERROR: Unknown option(s).\n");
    }

    printf("Usage: ListCerts FilePath\n");
}


int
main( int Argc, 
              char **Argv )
{
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_GUID   gSIGDB = EFI_IMAGE_SECURITY_DATABASE_GUID;
    EFI_GUID   owners[] = { EFI_GLOBAL_VARIABLE, EFI_GLOBAL_VARIABLE, gSIGDB, gSIGDB };
    char     *variables[] = { "PK", "KEK", "db", "dbx" };
	
	if (Argc == 2)
	{
        char *filepath = Argv[1];
        printf("2 Args, Argv[1]: %s\n", filepath);
		Status = OutputVariable(variables[2],owners[2], filepath);
	}
	else
	{
        printf("ARGC: %i\n", Argc);
		Usage(TRUE);
	}
	/*
    if (Argc == 1) {
        for (UINT8 i = 0; i < ARRAY_SIZE(owners); i++) {
            Status = OutputVariable(variables[i], owners[i]);
        }
    } else if (Argc == 2) {
        if (!StrCmp(Argv[1], L"--help") ||
            !StrCmp(Argv[1], L"-h")) { 
            Usage(FALSE);
            return Status;
        } else if (!StrCmp(Argv[1], L"--version") ||
            !StrCmp(Argv[1], L"-V")) {
            Print(L"Version: %s\n", UTILITY_VERSION);
            return Status;
        } else if (!StrCmp(Argv[1], L"-pk"))  {
            Status = OutputVariable(variables[0], owners[0]);
        } else if (!StrCmp(Argv[1], L"-kek"))  {
            Status = OutputVariable(variables[1], owners[1]);
        } else if (!StrCmp(Argv[1], L"-db"))  {
            Status = OutputVariable(variables[2], owners[2]);
        } else if (!StrCmp(Argv[1], L"-dbx"))  {
            Status = OutputVariable(variables[3], owners[3]);
        } else {
            Usage(TRUE);
        }
    } else if (Argc > 2) {
        Usage(TRUE);
    }*/

    return Status;
}
