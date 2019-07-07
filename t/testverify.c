#include "defs.h"
#include <stdio.h>
#include <assert.h>

void bin2hex(unsigned char *out, const char *in)
{
    char t;
    const char *p = in;
    unsigned char x;

    while (*p != '\0')
    {
        if (*p >= '0' && *p <= '9')
        {
            t = *p - '0';
        }
        else if (*p >= 'a' && *p <= 'z')
        {
            t = *p - 'a' + 10;
        }
        else
        {
            t = *p - 'A' + 10;
        }
        x = t << 4;
        p++;
        if (*p >= '0' && *p <= '9')
        {
            t = *p - '0';
        }
        else if (*p >= 'a' && *p <= 'z')
        {
            t = *p - 'a' + 10;
        }
        else
        {
            t = *p - 'A' + 10;
        }
        x += t;
        *out++ = x;
        p++;
    }
}

typedef struct
{
    const char *sk;
    const char *pk;
    const char *sign;
    const unsigned char *msg;
    unsigned long long mlen;
} test_t;

/* check sign, pk can't be NULL */
void testverify(const test_t *tests, int ntest)
{
    int j;
    unsigned char bpk[57];
    unsigned char bsign[114];
    for (j = 0; j < ntest; j++)
    {
        bin2hex(bpk, tests[j].pk);
        bin2hex(bsign, tests[j].sign);
        assert(crypto_sign_ed448_open_detached(tests[j].msg, tests[j].mlen, bsign, bpk) == 0);
        printf("test verify %d good\n", j);
    }
}

/* test vectors from rfc8032 */
const test_t tests[] = {
    {"6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b",
     "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180",
     "533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980"
     "ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600",
     NULL, 0},
    {"c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e",
     "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480",
     "26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f4352541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd77980"
     "5e0dbcc0aae1cbcee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0ff3348ab21aa4adafd1d234441cf807c03a00",
     (unsigned char *)"\x03", 1},
    {"cd23d24f714274e744343237b93290f511f6425f98e64459ff203e8985083ffdf60500553abc0e05cd02184bdb89c4ccd67e187951267eb328",
     "dcea9e78f35a1bf3499a831b10b86c90aac01cd84b67a0109b55a36e9328b1e365fce161d71ce7131a543ea4cb5f7e9f1d8b00696447001400",
     "1f0a8888ce25e8d458a21130879b840a9089d999aaba039eaf3e3afa090a09d389dba82c4ff2ae8ac5cdfb7c55e94d5d961a29fe0109941e00"
     "b8dbdeea6d3b051068df7254c0cdc129cbe62db2dc957dbb47b51fd3f213fb8698f064774250a5028961c9bf8ffd973fe5d5c206492b140e00",
     (unsigned char *)"\x0c\x3e\x54\x40\x74\xec\x63\xb0\x26\x5e\x0c", 11},
    {"258cdd4ada32ed9c9ff54e63756ae582fb8fab2ac721f2c8e676a72768513d939f63dddb55609133f29adf86ec9929dccb52c1c5fd2ff7e21b",
     "3ba16da0c6f2cc1f30187740756f5e798d6bc5fc015d7c63cc9510ee3fd44adc24d8e968b6e46e6f94d19b945361726bd75e149ef09817f580",
     "7eeeab7c4e50fb799b418ee5e3197ff6bf15d43a14c34389b59dd1a7b1b85b4ae90438aca634bea45e3a2695f1270f07fdcdf7c62b8efeaf00"
     "b45c2c96ba457eb1a8bf075a3db28e5c24f6b923ed4ad747c3c9e03c7079efb87cb110d3a99861e72003cbae6d6b8b827e4e6c143064ff3c00",
     (unsigned char *)"\x64\xa6\x5f\x3c\xde\xdc\xdd\x66\x81\x1e\x29\x15", 12},
    {"7ef4e84544236752fbb56b8f31a23a10e42814f5f55ca037cdcc11c64c9a3b2949c1bb60700314611732a6c2fea98eebc0266a11a93970100e",
     "b3da079b0aa493a5772029f0467baebee5a8112d9d3a22532361da294f7bb3815c5dc59e176b4d9f381ca0938e13c6c07b174be65dfa578e80",
     "6a12066f55331b6c22acd5d5bfc5d71228fbda80ae8dec26bdd306743c5027cb4890810c162c027468675ecf645a83176c0d7323a2ccde2d80"
     "efe5a1268e8aca1d6fbc194d3f77c44986eb4ab4177919ad8bec33eb47bbb5fc6e28196fd1caf56b4e7e0ba5519234d047155ac727a1053100",
     (unsigned char *)"\x64\xa6\x5f\x3c\xde\xdc\xdd\x66\x81\x1e\x29\x15\xe7", 13},
    {"d65df341ad13e008567688baedda8e9dcdc17dc024974ea5b4227b6530e339bff21f99e68ca6968f3cca6dfe0fb9f4fab4fa135d5542ea3f01",
     "df9705f58edbab802c7f8363cfe5560ab1c6132c20a9f1dd163483a26f8ac53a39d6808bf4a1dfbd261b099bb03b3fb50906cb28bd8a081f00",
     "554bc2480860b49eab8532d2a533b7d578ef473eeb58c98bb2d0e1ce488a98b18dfde9b9b90775e67f47d4a1c3482058efc9f40d2ca033a080"
     "1b63d45b3b722ef552bad3b4ccb667da350192b61c508cf7b6b5adadc2c8d9a446ef003fb05cba5f30e88e36ec2703b349ca229c2670833900",
     (unsigned char *)"\xbd\x0f\x6a\x37\x47\xcd\x56\x1b\xdd\xdf\x46\x40\xa3\x32\x46\x1a\x4a\x30\xa1\x2a\x43\x4c\xd0\xbf"
                      "\x40\xd7\x66\xd9\xc6\xd4\x58\xe5\x51\x22\x04\xa3\x0c\x17\xd1\xf5\x0b\x50\x79\x63\x1f\x64\xeb\x31"
                      "\x12\x18\x2d\xa3\x00\x58\x35\x46\x11\x13\x71\x8d\x1a\x5e\xf9\x44",
     64},
    {"2ec5fe3c17045abdb136a5e6a913e32ab75ae68b53d2fc149b77e504132d37569b7e766ba74a19bd6162343a21c8590aa9cebca9014c636df5",
     "79756f014dcfe2079f5dd9e718be4171e2ef2486a08f25186f6bff43a9936b9bfe12402b08ae65798a3d81e22e9ec80e7690862ef3d4ed3a00",
     "c650ddbb0601c19ca11439e1640dd931f43c518ea5bea70d3dcde5f4191fe53f00cf966546b72bcc7d58be2b9badef28743954e3a44a23f880"
     "e8d4f1cfce2d7a61452d26da05896f0a50da66a239a8a188b6d825b3305ad77b73fbac0836ecc60987fd08527c1a8e80d5823e65cafe2a3d00",
     (unsigned char *)"\x15\x77\x75\x32\xb0\xbd\xd0\xd1\x38\x9f\x63\x6c\x5f\x6b\x9b\xa7\x34\xc9\x0a\xf5\x72\x87\x7e\x2d"
                      "\x27\x2d\xd0\x78\xaa\x1e\x56\x7c\xfa\x80\xe1\x29\x28\xbb\x54\x23\x30\xe8\x40\x9f\x31\x74\x50\x41"
                      "\x07\xec\xd5\xef\xac\x61\xae\x75\x04\xda\xbe\x2a\x60\x2e\xde\x89\xe5\xcc\xa6\x25\x7a\x7c\x77\xe2"
                      "\x7a\x70\x2b\x3a\xe3\x9f\xc7\x69\xfc\x54\xf2\x39\x5a\xe6\xa1\x17\x8c\xab\x47\x38\xe5\x43\x07\x2f"
                      "\xc1\xc1\x77\xfe\x71\xe9\x2e\x25\xbf\x03\xe4\xec\xb7\x2f\x47\xb6\x4d\x04\x65\xaa\xea\x4c\x7f\xad"
                      "\x37\x25\x36\xc8\xba\x51\x6a\x60\x39\xc3\xc2\xa3\x9f\x0e\x4d\x83\x2b\xe4\x32\xdf\xa9\xa7\x06\xa6"
                      "\xe5\xc7\xe1\x9f\x39\x79\x64\xca\x42\x58\x00\x2f\x7c\x05\x41\xb5\x90\x31\x6d\xbc\x56\x22\xb6\xb2"
                      "\xa6\xfe\x7a\x4a\xbf\xfd\x96\x10\x5e\xca\x76\xea\x7b\x98\x81\x6a\xf0\x74\x8c\x10\xdf\x04\x8c\xe0"
                      "\x12\xd9\x01\x01\x5a\x51\xf1\x89\xf3\x88\x81\x45\xc0\x36\x50\xaa\x23\xce\x89\x4c\x3b\xd8\x89\xe0"
                      "\x30\xd5\x65\x07\x1c\x59\xf4\x09\xa9\x98\x1b\x51\x87\x8f\xd6\xfc\x11\x06\x24\xdc\xbc\xde\x0b\xf7"
                      "\xa6\x9c\xcc\xe3\x8f\xab\xdf\x86\xf3\xbe\xf6\x04\x48\x19\xde\x11",
     256}};

int main()
{
    testverify(tests, 7);
    return 0;
}
