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
#define TMP_BUFF_SIZE 1000
#define BUFF_SIZE 3000
#define CERT_BUFF 100
#define DO_ALGORITHM_BUFF 200
#define DO_EXTENSION_ID_BUFF 120
#define DO_ATTRIBUTE_TYPE_BUFF 120

// temporary store for output text
wchar_t tmpbuf[TMP_BUFF_SIZE];
wchar_t outbuf[BUFF_SIZE];
unsigned int bufsize = BUFF_SIZE;
unsigned int bufutil;
unsigned int tmpsize = TMP_BUFF_SIZE;
unsigned int tmputil;


wchar_t cert_buff[CERT_BUFF];
unsigned int certbuff = CERT_BUFF;
size_t wrapno = 1;
unsigned int sizeofchar = sizeof(char);



/**
 * Function prototypes to make it easier to inventory, track, and document program structure
 */
void fix_print_output();
void FillTmpbuf(wchar_t* data, int catenate);
int CompareGuid(GUID* first, GUID* second);
wchar_t* AsciiToUnicode(const char* Str, size_t Len);
char* make_utc_date_string(char* s);
void GetCertType(GUID* certGUID, wchar_t** typeName);
/*start sourced from x509.h*/
int do_algorithm(void* context, long state_index, unsigned char tag, const void* value, size_t vlen);
int do_attribute_type(void* context, long state_index, unsigned char tag, const void* value, size_t vlen);
int do_attribute_value(void* context, long state_index, unsigned char tag, const void* value, size_t vlen);
int do_extension_id(void* context, long state_index, unsigned char tag, const void* value, size_t vlen);
int do_extensions(void* context, long state_index, unsigned char tag, const void* value, size_t vlen);
int do_issuer(void* context, long  state_index, unsigned char tag, const void* value, size_t vlen);
int do_serialnumber(void* context, long state_index, unsigned char tag, const void* value, size_t vlen);
int do_signature(void* context, long state_index, unsigned char tag, const void* value, size_t vlen);
int do_subject(void* context, long state_index, unsigned char tag, const void* value, size_t vlen);
int do_subject_public_key_info(void* context, long state_index, unsigned char tag, const void* value, size_t vlen);
int do_validity_not_after(void* context, long state_index, unsigned char tag, const void* value, size_t vlen);
int do_validity_not_before(void* context, long state_index, unsigned char tag, const void* value, size_t vlen);
int do_version(void* context, long state_index, unsigned char tag, const void* value, size_t vlen);
/*end sourced from x509.h*/
int PrintCertificates(unsigned char* data, unsigned int len, FILE** fp);
EFI_STATUS get_variable(char *filepath, unsigned char* Data, unsigned int* Len, FILE** fp);
EFI_STATUS OutputVariable(char *filepath);
VOID Usage(BOOLEAN ErrorMsg);
int main(int Argc, char** Argv);

void fix_print_output()
{
    for (unsigned int i = 0; i < bufutil; i++)
    {
        if (outbuf[i] == 0)
        {
            outbuf[i] = 32; // ' '
        }
    }
    outbuf[bufutil] = 0;
}

void FillTmpbuf(wchar_t* data, int catenate)
{
    if (catenate == 0)
    {
        tmputil = 0;
    }
    tmputil += swprintf_s(tmpbuf + tmputil, tmpsize - tmputil, L"%ls", data);
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

wchar_t*
AsciiToUnicode(const char* Str,
    size_t Len)
{
    wchar_t *Ret = NULL;
    Ret = calloc(Len, sizeof(wchar_t));

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

void GetCertType(GUID* certGUID, wchar_t** typeName)
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
    
    wchar_t* type;

    if (CompareGuid(certGUID, &gX509) == 0)
        type = L"X509";
    else if (CompareGuid(certGUID, &gPKCS7) == 0)
        type = L"PKCS7";
    else if (CompareGuid(certGUID, &gRSA2048) == 0)
        type = L"RSA2048";
    else if (CompareGuid(certGUID, &gSHA256) == 0)
        type = L"SHA256";
    else if (CompareGuid(certGUID, &gRSA2048SHA256) == 0)
        type = L"RSA2048SHA256";
    else if (CompareGuid(certGUID, &gSHA1) == 0)
        type = L"SHA1";
    else if (CompareGuid(certGUID, &gRSA2048SHA1) == 0)
        type = L"RSA2048SHA1";
    else if (CompareGuid(certGUID, &gSHA224) == 0)
        type = L"SHA224";
    else if (CompareGuid(certGUID, &gSHA384) == 0)
        type = L"SHA384";
    else if (CompareGuid(certGUID, &gSHA512) == 0)
        type = L"SHA512";
    else if (CompareGuid(certGUID, &gX509SHA256) == 0)
        type = L"X509SHA256";
    else if (CompareGuid(certGUID, &gX509SHA384) == 0)
        type = L"X509SHA384";
    else if (CompareGuid(certGUID, &gX509SHA512) == 0)
        type = L"X509SHA512";
    else
        type = L"UNKNOWN";
    
    
    swprintf_s(*typeName, certbuff, L"%ls", type);
}

int
do_algorithm(void* context,
    long state_index,
    unsigned char tag,
    const void* value,
    size_t vlen)
{
    enum OID oid;
    int catenate = 0;

    wchar_t buffer[DO_ALGORITHM_BUFF];
    wchar_t* val = 0;
    size_t size;
    
    oid = Lookup_OID(value, vlen);
    
    switch (oid)
    {
    case OID_id_dsa_with_sha1: val = L"id_dsa_with_sha1";
        break;
    case OID_id_dsa: val = L"id_dsa";
        break;
    case OID_id_ecdsa_with_sha1: val = L"id_ecdsa_with_sha1";
        break;
    case OID_id_ecPublicKey: val = L"id_ecPublicKey";
        break;
    case OID_rsaEncryption: val = L"rsaEncryption";
        break;
    case OID_md2WithRSAEncryption: val = L"md2WithRSAEncryption";
        break;
    case OID_md3WithRSAEncryption: val = L"md3WithRSAEncryption";
        break;
    case OID_md4WithRSAEncryption: val = L"md4WithRSAEncryption";
        break;
    case OID_sha1WithRSAEncryption: val = L"sha1WithRSAEncryption";
        break;
    case OID_sha256WithRSAEncryption: val = L"sha256WithRSAEncryption";
        break;
    case OID_sha384WithRSAEncryption: val = L"sha384WithRSAEncryption";
        break;
    case OID_sha512WithRSAEncryption: val = L"sha512WithRSAEncryption";
        break;
    case OID_sha224WithRSAEncryption: val = L"sha224WithRSAEncryption";
        break;
    default:
        catenate = 1;
        
        memset(buffer, 0, DO_ALGORITHM_BUFF);
        Sprint_OID(value, vlen, buffer, DO_ALGORITHM_BUFF);
        size = wcsnlen_s(buffer, DO_ALGORITHM_BUFF);

        val = calloc(size + 4, sizeof(wchar_t));
        memcpy_s((val + 2), size, buffer, size);
        val[0] = 32; // ' '
        val[1] = 40; // '('
        val[size + 1] = 41; // ')'
        val[size + 2] = 0;
        
        break;
    }

    FillTmpbuf(val, catenate);
    //free(buffer);

    return 0;
}

int
do_extension_id(void* context,
    long state_index,
    unsigned char tag,
    const void* value,
    size_t vlen)
{
    enum OID oid;
    int catenate = 1;

    wchar_t buffer[DO_EXTENSION_ID_BUFF];
    wchar_t* val = 0;
    size_t size;

    
    size_t len = wcsnlen(tmpbuf, TMP_BUFF_SIZE);
    if (len > (90 * wrapno)) {
        // Not sure why a CR is now required in UDK2017.  Need to investigate
        //FillTmpbuf(L"\r\n             ", catenate);
        FillTmpbuf(L"\n             ", catenate);
        wrapno++;
    }
    

    oid = Lookup_OID(value, vlen);
    switch (oid)
    {
    case OID_subjectKeyIdentifier: val = L"SubjectKeyIdentifier";
        break;
    case OID_keyUsage: val = L"KeyUsage";
        break;
    case OID_subjectAltName: val = L"SubjectAltName";
        break;
    case OID_issuerAltName: val = L"IssuerAltName";
        break;
    case OID_basicConstraints: val = L"BasicConstraints";
        break;
    case OID_crlDistributionPoints: val = L"CrlDistributionPoints";
        break;
    case OID_certAuthInfoAccess: val = L"CertAuthInfoAccess";
        break;
    case OID_certPolicies: val = L"CertPolicies";
        break;
    case OID_authorityKeyIdentifier: val = L"AuthorityKeyIdentifier";
        break;
    case OID_extKeyUsage: val = L"ExtKeyUsage";
        break;
    case OID_msEnrollCerttypeExtension: val = L"msEnrollCertTypeExtension";
        break;
    case OID_msCertsrvCAVersion: val = L"msCertsrvCAVersion";
        break;
    case OID_msCertsrvPreviousCertHash: val = L"msCertsrvPreviousCertHash";
        break;
    default:

        memset(buffer, 0, DO_EXTENSION_ID_BUFF);
        Sprint_OID(value, vlen, buffer, DO_EXTENSION_ID_BUFF);
        size = wcsnlen_s(buffer, DO_EXTENSION_ID_BUFF);

        val = calloc(size + 4, sizeof(wchar_t));
        memcpy_s((val + 2), size, buffer, size);
        val[0] = 32; // ' '
        val[1] = 40; // '('
        val[size + 1] = 41; // ')'
        val[size + 2] = 0;
        
        break;
    }

    FillTmpbuf(val, catenate);

    return 0;
}

int
do_attribute_type(void* context,
    long state_index,
    unsigned char tag,
    const void* value,
    size_t vlen)
{
    enum OID oid;
    int catenate = 1;

    wchar_t buffer[DO_ATTRIBUTE_TYPE_BUFF];
    wchar_t* val = 0;
    size_t size;
    
    oid = Lookup_OID(value, vlen);
    
    switch (oid)
    {
    case OID_countryName: val = L" C=";
        break;
    case OID_stateOrProvinceName: val = L" ST=";
        break;
    case OID_locality: val = L" L=";
        break;
    case OID_organizationName: val = L" O=";
        break;
    case OID_commonName: val = L" CN=";
        break;
    default:

        memset(buffer, 0, DO_ATTRIBUTE_TYPE_BUFF);
        Sprint_OID(value, vlen, buffer, DO_ATTRIBUTE_TYPE_BUFF);
        size = wcsnlen_s(buffer, DO_ATTRIBUTE_TYPE_BUFF);

        val = calloc(size + 4, sizeof(wchar_t));
        memcpy_s((val + 2), size, buffer, size);
        val[0] = 32; // ' '
        val[1] = 40; // '('
        val[size + 1] = 41; // ')'
        val[size + 2] = 0;

        break;
    }

    FillTmpbuf(val, catenate);
    //free(buffer);

    return 0;
}

int 
do_version( void *context, 
            long state_index,
            unsigned char tag,
            const void *value, 
            size_t vlen )
{
    int Version = *(const char *)value;

    bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"\tVersion: %d (0x%02x) ", Version + 1, Version);

    return 0;
}


int
do_signature( void *context, 
              long state_index,
              unsigned char tag,
              const void *value,
              size_t vlen )
{
    bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"\n\tSignature Algorithm: %ls\n", tmpbuf);
    
    tmpbuf[0] = '\0';
    tmputil = 0;

    return 0;
}


int 
do_serialnumber( void *context, 
                 long state_index,
                 unsigned char tag,
                 const void *value, 
                 size_t vlen )
{
    wchar_t *p = 0; 
    p = AsciiToUnicode(value,strlen(value));

    bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"\tSerial Number: ");
    if (vlen > 4) {
        for (size_t i = 0; i < vlen; i++, p++) {
            bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"%02x%wc", *p, ((i + 1 == vlen) ? ' ' : ':'));
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
           size_t vlen )
{
    bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"\tIssuer: %ls\n", tmpbuf);
    
    tmpbuf[0] = '\0';
    tmputil = 0;

    return 0;
}


int
do_subject( void *context,
            long state_index,
            unsigned char tag,
            const void *value,
            size_t vlen )
{
    bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"\tSubject:%ls\n", tmpbuf);
    
    tmpbuf[0] = '\0';
    tmputil = 0;

    return 0;
}


int
do_attribute_value( void *context,
                    long state_index,
                    unsigned char tag,
                    const void *value,
                    size_t vlen )
{
    wchar_t *ptr;

    ptr = AsciiToUnicode(value, vlen);
    FillTmpbuf(ptr, 1);
    free(ptr);

    return 0;
}


int
do_extensions( void *context,
               long state_index,
               unsigned char tag,
               const void *value,
               size_t vlen )
{
    bufutil += swprintf_s(outbuf + bufutil,bufsize - bufutil, L"\tExtensions:%ls\n", tmpbuf);
    
    tmpbuf[0] = '\0';
    tmputil = 0;
    wrapno = 1;

    return 0;
}

int
do_validity_not_before( void *context,
                        long state_index,
                        unsigned char tag,
                        const void *value, 
                        size_t vlen )
{
    wchar_t *ptr;
    char *p;

    p = make_utc_date_string((char *)value);
    ptr = AsciiToUnicode(p, UTCDATE_LEN);
    bufutil += swprintf_s(outbuf + bufutil,bufsize - bufutil, L"\n\tValidity:  Not Before: %ls\n", ptr);
    free(ptr);

    return 0;
}


int
do_validity_not_after( void *context,
                       long state_index,
                       unsigned char tag,
                       const void *value,
                       size_t vlen )
{
    wchar_t *ptr;
    char *p;

    p = make_utc_date_string((char *)value);
    ptr = AsciiToUnicode(p, UTCDATE_LEN);
    bufutil += swprintf_s(outbuf + bufutil,bufsize - bufutil, L"\n\tNot After: %ls\n", ptr);
    free(ptr);

    return 0;
}


int
do_subject_public_key_info( void *context, 
                            long state_index,
                            unsigned char tag,
                            const void *value, 
                            size_t vlen )
{
    bufutil += swprintf_s(outbuf + bufutil,bufsize - bufutil, L"\n\tSubject Public Key Algorithm: %ls\n", tmpbuf);
    
    tmpbuf[0] = '\0';
    tmputil = 0;

    return 0;
}

int
PrintCertificates( unsigned char *data, 
                   unsigned int len, 
                   FILE **fp )
{
    fread_s(data,8000, sizeofchar, len, *fp);
	
    EFI_SIGNATURE_LIST *CertList = (EFI_SIGNATURE_LIST *)data;
    EFI_SIGNATURE_DATA *Cert;
    wchar_t *certType = calloc(certbuff, sizeof(wchar_t));
    BOOLEAN  CertFound = FALSE;
    unsigned int    DataSize = len;
    unsigned int    CertCount = 0;
    unsigned int    buflen;
    int      status = 0;
	
    /*Certificate output buffer setup*/
    memset(outbuf, 0, bufsize);
    bufutil = 0;

    while ((DataSize > 0) && (DataSize >= CertList->SignatureListSize)) {
        CertCount = (CertList->SignatureListSize - CertList->SignatureHeaderSize) / CertList->SignatureSize;
        Cert = (EFI_SIGNATURE_DATA *) ((unsigned char *) CertList + sizeof (EFI_SIGNATURE_LIST) + CertList->SignatureHeaderSize);

        memset(certType, 0, certbuff);

        // should all be X509 but just in case...
        GetCertType(&(CertList->SignatureType), &certType);
        
        for (unsigned int Index = 0; Index < CertCount; Index++) {
            if ( CertList->SignatureSize > 100 ) {
                CertFound = TRUE;
                //outbuf[0] = '\0';
                bufutil += swprintf_s(outbuf + bufutil, (bufsize - bufutil) , L"\n\nType: %ls  (GUID: %hs)\n", certType, &Cert->SignatureOwner.Data4); //TODO: warning C4477 : 'swprintf_s' : format string '%g' requires an argument of type 'double', but variadic argument 2 has type 'EFI_GUID *'
                //printf("%s", outbuf);
                //outbuf[0] = '\0';
                buflen  = CertList->SignatureSize - sizeof(EFI_GUID);
                status = asn1_ber_decoder(&x509_decoder, NULL, Cert->SignatureData, buflen); //x509_decoder from x509.h, which loads functions above (clever)
                fix_print_output();
                printf("%ls\n", outbuf);
                memset(outbuf, 0, bufsize);
                bufutil = 0;
            }
            Cert = (EFI_SIGNATURE_DATA *) ((unsigned char *) Cert + CertList->SignatureSize);
        }
        DataSize -= CertList->SignatureListSize;
        CertList = (EFI_SIGNATURE_LIST *) ((unsigned char *) CertList + CertList->SignatureListSize);
    }

    if ( CertFound == FALSE ) {
       printf("\nNo certificates found for this database\n");
    }
    free(certType);

    return status;
}

EFI_STATUS
get_variable( char *filepath, 
              unsigned char *Data, 
              unsigned int *Len,
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
    unsigned char *Data = calloc(8000,sizeofchar); //TODO: hardcoding because I just want to process the DBX update for now
    unsigned int Len = 8000;
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
        bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"ERROR: Failed to get open %hs. Status Code: %I64d\n", filepath, Status);
        printf("%ls", outbuf);
        return Status;
    }
    else
    {
        memset(outbuf, 0, bufsize);
        bufutil += swprintf_s(outbuf + bufutil, bufsize - bufutil, L"ERROR: Failed to get open %hs. Status Code: %I64d\n", filepath, Status);
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
