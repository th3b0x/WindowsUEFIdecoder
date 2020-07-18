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
#define DEBUG
#define BUFF_SIZE 3000
#define CERT_BUFF 100
#define DO_ALGORITHM_BUFF 200
#define DO_EXTENSION_ID_BUFF 120
#define DO_ATTRIBUTE_TYPE_BUFF 120

// temporary store for output text
char tmpbuf[1000];
char outbuf[BUFF_SIZE];
unsigned int bufsize = BUFF_SIZE;
unsigned int bufutil;
long doalgobuff = DO_ALGORITHM_BUFF;
long doextbuff = DO_EXTENSION_ID_BUFF;
long doatttypebuff = DO_ATTRIBUTE_TYPE_BUFF;
long certbuff = CERT_BUFF;
int    wrapno = 1;
unsigned int sizeofchar = sizeof(char);



/**
 * Function prototypes to make it easier to inventory, track, and document program structure
 */
rsize_t strlen_s(char* str);
int CompareGuid(GUID* first, GUID* second);
char* AsciiToUnicode(const char* Str, int Len);
char* make_utc_date_string(char* s);
void GetCertType(GUID* certGUID, char** typeName);
int do_algorithm(void* context, long state_index, unsigned char tag, const void* value, long vlen);
int do_extension_id(void* context, long state_index, unsigned char tag, const void* value, long vlen);
int do_version(void* context, long state_index, unsigned char tag, const void* value, long vlen);
int do_signature(void* context, long state_index, unsigned char tag, const void* value, long vlen);
int do_serialnumber(void* context, long state_index, unsigned char tag, const void* value, long vlen);
int do_issuer(void* context, long  state_index, unsigned char tag, const void* value, long vlen);
int do_subject(void* context, long state_index, unsigned char tag, const void* value, long vlen);
int do_attribute_type(void* context, long state_index, unsigned char tag, const void* value, long vlen);
int do_attribute_value(void* context, long state_index, unsigned char tag, const void* value, long vlen);
int do_extensions(void* context, long state_index, unsigned char tag, const void* value, long vlen);
int do_validity_not_before(void* context, long state_index, unsigned char tag, const void* value, long vlen);
int do_validity_not_after(void* context, long state_index, unsigned char tag, const void* value, long vlen);
int do_subject_public_key_info(void* context, long state_index, unsigned char tag, const void* value, long vlen);
int PrintCertificates(UINT8* data, UINTN len, FILE** fp);
EFI_STATUS get_variable(char *filepath, UINT8* Data, UINTN* Len, FILE** fp);
EFI_STATUS OutputVariable(char *filepath);
VOID Usage(BOOLEAN ErrorMsg);
int main(int Argc, char** Argv);

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

char*
AsciiToUnicode(const char* Str,
    int Len)
{
    char* Ret = NULL;
    Ret = calloc((Len * 2 + 2), sizeofchar);

    if (!Ret)
        return NULL;

    for (int i = 0; i < Len; i++)
        Ret[i] = Str[i];

    return Ret;
}

//
//  Yes, a hack but it works!
//
char*
make_utc_date_string(char* s)
{
    static char buffer[50];
    char* d;

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
        swprintf_s(*typeName, certbuff, L"%ls", L"X509");
    else if (CompareGuid(certGUID, &gPKCS7) == 0)
        swprintf_s(*typeName, certbuff, L"%ls", L"PKCS7");
    else if (CompareGuid(certGUID, &gRSA2048) == 0)
        swprintf_s(*typeName, certbuff, L"%ls", L"RSA2048");
    else if (CompareGuid(certGUID, &gSHA256) == 0)
        swprintf_s(*typeName, certbuff, L"%ls", L"SHA256");
    else if (CompareGuid(certGUID, &gRSA2048SHA256) == 0)
        swprintf_s(*typeName, certbuff, L"%ls", L"RSA2048SHA256");
    else if (CompareGuid(certGUID, &gSHA1) == 0)
        swprintf_s(*typeName, certbuff, L"%ls", L"SHA1");
    else if (CompareGuid(certGUID, &gRSA2048SHA1) == 0)
        swprintf_s(*typeName, certbuff, L"%ls", L"RSA2048SHA1");
    else if (CompareGuid(certGUID, &gSHA224) == 0)
        swprintf_s(*typeName, certbuff, L"%ls", L"SHA224");
    else if (CompareGuid(certGUID, &gSHA384) == 0)
        swprintf_s(*typeName, certbuff, L"%ls", L"SHA384");
    else if (CompareGuid(certGUID, &gSHA512) == 0)
        swprintf_s(*typeName, certbuff, L"%ls", L"SHA512");
    else if (CompareGuid(certGUID, &gX509SHA256) == 0)
        swprintf_s(*typeName, certbuff, L"%ls", L"X509SHA256");
    else if (CompareGuid(certGUID, &gX509SHA384) == 0)
        swprintf_s(*typeName, certbuff, L"%ls", L"X509SHA384");
    else if (CompareGuid(certGUID, &gX509SHA512) == 0)
        swprintf_s(*typeName, certbuff, L"%ls", L"X509SHA512");
    else
        swprintf_s(*typeName, certbuff, L"%ls", L"UNKNOWN");
}

int
do_algorithm(void* context,
    long state_index,
    unsigned char tag,
    const void* value,
    long vlen)
{
    enum OID oid;
    /*char* buffer = NULL;
    buffer = calloc(doalgobuff, sizeofchar);*/
    CHAR16 buffer[DO_ALGORITHM_BUFF];
    memset(buffer, 0, DO_ALGORITHM_BUFF);

    oid = Lookup_OID(value, vlen);
    Sprint_OID(value, vlen, buffer, sizeof(buffer));
    if (oid == OID_id_dsa_with_sha1)
        bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"%ls", L"id_dsa_with_sha1");
    else if (oid == OID_id_dsa)
        bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"%ls", L"id_dsa");
    else if (oid == OID_id_ecdsa_with_sha1)
        bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"%ls", L"id_ecdsa_with_sha1");
    else if (oid == OID_id_ecPublicKey)
        bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"%ls", L"id_ecPublicKey");
    else if (oid == OID_rsaEncryption)
        bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"%ls", L"rsaEncryption");
    else if (oid == OID_md2WithRSAEncryption)
        bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"%ls", L"md2WithRSAEncryption");
    else if (oid == OID_md3WithRSAEncryption)
        bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"%ls", L"md3WithRSAEncryption");
    else if (oid == OID_md4WithRSAEncryption)
        bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"%ls", L"md4WithRSAEncryption");
    else if (oid == OID_sha1WithRSAEncryption)
        bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"%ls", L"sha1WithRSAEncryption");
    else if (oid == OID_sha256WithRSAEncryption)
        bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"%ls", L"sha256WithRSAEncryption");
    else if (oid == OID_sha384WithRSAEncryption)
        bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"%ls", L"sha384WithRSAEncryption");
    else if (oid == OID_sha512WithRSAEncryption)
        bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"%ls", L"sha512WithRSAEncryption");
    else if (oid == OID_sha224WithRSAEncryption)
        bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"%ls", L"sha224WithRSAEncryption");
    else {
        bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"%ls", L" (");
        bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"%ls", buffer);
        bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"%ls", L")");
    }

    //free(buffer);

    return 0;
}

int
do_extension_id(void* context,
    long state_index,
    unsigned char tag,
    const void* value,
    long vlen)
{
    enum OID oid;
    /*char* buffer = NULL;
    buffer = calloc(doextbuff, sizeofchar);*/
    CHAR16 buffer[DO_EXTENSION_ID_BUFF];
    memset(buffer, 0, DO_EXTENSION_ID_BUFF);
    int len = strlen_s(tmpbuf);

    if (len > (90 * wrapno)) {
        // Not sure why a CR is now required in UDK2017.  Need to investigate
        bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"%ls", L"\r\n             ");
        wrapno++;
    }

    oid = Lookup_OID(value, vlen);
    Sprint_OID(value, vlen, buffer, sizeof(buffer));

    if (oid == OID_subjectKeyIdentifier)
        bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"%ls", L" SubjectKeyIdentifier");
    else if (oid == OID_keyUsage)
        bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"%ls", L" KeyUsage");
    else if (oid == OID_subjectAltName)
        bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"%ls", L" SubjectAltName");
    else if (oid == OID_issuerAltName)
        bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"%ls", L" IssuerAltName");
    else if (oid == OID_basicConstraints)
        bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"%ls", L" BasicConstraints");
    else if (oid == OID_crlDistributionPoints)
        bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"%ls", L" CrlDistributionPoints");
    else if (oid == OID_certAuthInfoAccess)
        bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"%ls", L" CertAuthInfoAccess");
    else if (oid == OID_certPolicies)
        bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"%ls", L" CertPolicies");
    else if (oid == OID_authorityKeyIdentifier)
        bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"%ls", L" AuthorityKeyIdentifier");
    else if (oid == OID_extKeyUsage)
        bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"%ls", L" ExtKeyUsage");
    else if (oid == OID_msEnrollCerttypeExtension)
        bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"%ls", L" msEnrollCertTypeExtension");
    else if (oid == OID_msCertsrvCAVersion)
        bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"%ls", L" msCertsrvCAVersion");
    else if (oid == OID_msCertsrvPreviousCertHash)
        bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"%ls", L" msCertsrvPreviousCertHash");
    else {
        bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"%ls", L" (");
        bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"%ls", buffer);
        bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"%ls", L")");
    }

    //free(buffer);

    return 0;
}

//TODO: revisit this and re-implement using swprintf_s
int
do_attribute_type(void* context,
    long state_index,
    unsigned char tag,
    const void* value,
    long vlen)
{
    enum OID oid;
    CHAR16 buffer[DO_ATTRIBUTE_TYPE_BUFF];
    memset(buffer, 0, DO_ATTRIBUTE_TYPE_BUFF);
    /*char* buffer = NULL;
    buffer = calloc(doatttypebuff, sizeofchar);*/

    oid = Lookup_OID(value, vlen);
    Sprint_OID(value, vlen, buffer, sizeof(buffer));

    if (oid == OID_countryName) {
        bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"%ls", L" C=");
    }
    else if (oid == OID_stateOrProvinceName) {
        bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"%ls", L" ST=");
    }
    else if (oid == OID_locality) {
        bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"%ls", L" L=");
    }
    else if (oid == OID_organizationName) {
        bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"%ls", L" O=");
    }
    else if (oid == OID_commonName) {
        bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"%ls", L" CN=");
    }
    else {
        bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"%ls", L" (");
        bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"%ls", buffer);
        bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"%ls", L")");
    }

    //free(buffer);

    return 0;
}

int 
do_version( void *context, 
            long state_index,
            unsigned char tag,
            const void *value, 
            long vlen )
{
    int Version = *(const char *)value;

    bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"  Version: %d (0x%02x) ", Version + 1, Version);

    return 0;
}


int
do_signature( void *context, 
              long state_index,
              unsigned char tag,
              const void *value,
              long vlen )
{
    bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"  Signature Algorithm: %ls\n", tmpbuf);
    tmpbuf[0] = '\0';

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

    bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"  Serial Number: ");
    if (vlen > 4) {
        for (int i = 0; i < vlen; i++, p++) {
            bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"%02x%c", (UINT8)*p, ((i + 1 == vlen) ? ' ' : ':'));
        }
    }
    bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"%ls", L"\n");

    return 0;
}


int
do_issuer( void *context,
           long  state_index,
           unsigned char tag,
           const void *value,
           long vlen )
{
    bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"  Issuer:%ls\n", tmpbuf);
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
    bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"  Subject:%ls\n", tmpbuf);
    tmpbuf[0] = '\0';

    return 0;
}


int
do_attribute_value( void *context,
                    long state_index,
                    unsigned char tag,
                    const void *value,
                    long vlen )
{
    char *ptr;

    ptr = AsciiToUnicode(value, (int)vlen);
    bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"%ls",ptr);
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
    bufutil += swprintf_s(outbuf + bufutil,bufsize - bufutil, L"  Extensions:%ls\n", tmpbuf);
    tmpbuf[0] = '\0';
    wrapno = 1;

    return 0;
}

int
do_validity_not_before( void *context,
                        long state_index,
                        unsigned char tag,
                        const void *value, 
                        long vlen )
{
    char *ptr;
    char *p;

    p = make_utc_date_string((char *)value);
    ptr = AsciiToUnicode(p, UTCDATE_LEN);
    bufutil += swprintf_s(outbuf + bufutil,bufsize - bufutil, L"  Validity:  Not Before: %ls", ptr);
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
    char *ptr;
    char *p;

    p = make_utc_date_string((char *)value);
    ptr = AsciiToUnicode(p, UTCDATE_LEN);
    bufutil += swprintf_s(outbuf + bufutil,bufsize - bufutil, L"   Not After: %ls\n", ptr);
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
    bufutil += swprintf_s(outbuf + bufutil,bufsize - bufutil, L"  Subject Public Key Algorithm: %ls\n", tmpbuf);
    tmpbuf[0] = '\0';

    return 0;
}

int
PrintCertificates( UINT8 *data, 
                   UINTN len, 
                   FILE **fp )
{
    fread_s(data,8000, sizeofchar, len, *fp);
	
    EFI_SIGNATURE_LIST *CertList = (EFI_SIGNATURE_LIST *)data;
    EFI_SIGNATURE_DATA *Cert;
    char* certType = calloc(certbuff, sizeofchar);
    BOOLEAN  CertFound = FALSE;
    UINTN    DataSize = len;
    UINTN    CertCount = 0;
    UINTN    buflen;
    int      status = 0;
	
    /*Certificate output buffer setup*/
    memset(outbuf, 0, bufsize);
    bufutil = 1;

    while ((DataSize > 0) && (DataSize >= CertList->SignatureListSize)) {
        CertCount = (CertList->SignatureListSize - CertList->SignatureHeaderSize) / CertList->SignatureSize;
        Cert = (EFI_SIGNATURE_DATA *) ((UINT8 *) CertList + sizeof (EFI_SIGNATURE_LIST) + CertList->SignatureHeaderSize);

        memset(certType, 0, certbuff);

        // should all be X509 but just in case...
        GetCertType(&(CertList->SignatureType), &certType);
        
        for (UINTN Index = 0; Index < CertCount; Index++) {
            if ( CertList->SignatureSize > 100 ) {
                CertFound = TRUE;
                //outbuf[0] = '\0';
                bufutil += swprintf_s(outbuf + bufutil, (bufsize - bufutil) , L"\nType: %ls  (GUID: %g)\n", certType, &Cert->SignatureOwner);
                //printf("%s", outbuf);
                //outbuf[0] = '\0';
                buflen  = CertList->SignatureSize - sizeof(EFI_GUID);
                status = asn1_ber_decoder(&x509_decoder, NULL, Cert->SignatureData, buflen); //x509_decoder from x509.h, which loads functions above (clever)
                printf("%ls", outbuf);
                memset(outbuf, 0, bufsize);
                bufutil = 1;
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

EFI_STATUS
get_variable( char *filepath, 
              UINT8 *Data, 
              UINTN *Len,
              FILE **fp )
{
    EFI_STATUS Status = EFI_SUCCESS;

    int err = 0;
    *Len = 0;
    
    #ifdef DEBUG
    printf("Prepping to open file %s\n",filepath);
    #endif
    
    err = fopen_s(fp, filepath, "rb");
        
    if (err == 0)
    {
        while (fgetc(*fp) != EOF)
        {
            *Len = *Len + 1;
        }
        fclose(*fp);
        fopen_s(fp, filepath, "rb");

        #ifdef DEBUG
        printf("Success Opening\n");
        #endif

        Status = EFI_SUCCESS;
    }
    else
    {
        #ifdef DEBUG
        printf("Error Opening\n");
        #endif  
        
        Status = EFI_LOAD_ERROR;
    }

    return Status;
}

EFI_STATUS OutputVariable( char *filepath) 
{
    const char* _failedToOpenFileErr = "ERROR: Failed to get open %s. Status Code: %d\n";

    EFI_STATUS Status = EFI_SUCCESS;
    UINT8 *Data = calloc(8000,sizeofchar); //TODO: hardcoding because I just want to process the DBX update for now
    UINTN Len = 8000;
    FILE *fp = calloc(1, sizeof(FILE));

    #ifdef DEBUG
    printf("Prepping to get data\n");
    #endif

    Status = get_variable( filepath, Data, &Len, &fp );
    if (Status == EFI_SUCCESS) {
        #ifdef DEBUG
        printf("\nFILEPATH: %s  (pointer: %p)\n", filepath, &fp);
        #endif
        
        PrintCertificates( Data, Len, &fp );
        
    } else if (Status == EFI_NOT_FOUND) {
        memset(outbuf, 0, bufsize);
        bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"ERROR: Failed to get open %ls. Status Code: %I64d\n", filepath, Status);
        printf("%ls", outbuf);
        return Status;
    }
    else
    {
        memset(outbuf, 0, bufsize);
        bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"ERROR: Failed to get open %ls. Status Code: %I64d\n", filepath, Status);
        printf("%ls", outbuf);
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
	
	if (Argc == 2)
	{
        char *filepath = Argv[1];
        printf("2 Args, Argv[1]: %s\n", filepath);
		Status = OutputVariable(filepath);
	}
	else
	{
        printf("ARGC: %i\n", Argc);
		Usage(TRUE);
	}

    return Status;
}
