// ============================================================
//  SFHook Tweak —— 顺丰 iOS 加密入参 Hook
//  目标：dump 出 sytToken / 盐 / AES key 的原始输入
//  原理：hook CommonCrypto 底层函数（CC_MD5 / CC_SHA* / CC_SHA3 / CCCrypt / PBKDF）+ RN 模块调用
//  日志：/tmp/sf_hook.log  和  App Documents/sf_hook.log
//  用法：theos 编译 -> make package -> 解出 .dylib -> TrollStore/ellekit 注入顺丰 App
// ============================================================

#import <substrate.h>
#import "fishhook.h"

#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonKeyDerivation.h>
#import <CommonCrypto/CommonHMAC.h>

#import <dlfcn.h>
#import <objc/runtime.h>
#import <Foundation/Foundation.h>

// ---------- 日志工具 ----------
static int sf_fd = -1;

static void sf_open_log(void) {
    if (sf_fd >= 0) return;
    // 首选 /tmp（TrollStore 环境可写，Filza/SSH 可看）
    const char *paths[] = {"/tmp/sf_hook.log", NULL};
    sf_fd = open(paths[0], O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (sf_fd < 0) {
        // 回退到 App Documents
        NSArray *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
        if (docs.count) {
            NSString *p = [docs[0] stringByAppendingPathComponent:@"sf_hook.log"];
            sf_fd = open(p.UTF8String, O_WRONLY | O_CREAT | O_APPEND, 0644);
        }
    }
}

static void sf_log(const char *fmt, ...) {
    sf_open_log();
    char buf[4096];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n < 0) n = 0;
    if (n >= (int)sizeof(buf)) n = sizeof(buf) - 1;
    if (sf_fd >= 0) write(sf_fd, buf, n);
    fprintf(stderr, "%s", buf);  // 同时走 syslog，方便 log stream 看
}

// 把一段内存 dump 成 hex + 可读 UTF-8 字符串
static void sf_dump(const char *tag, const void *data, size_t len) {
    if (len == 0 || data == NULL) {
        sf_log("[SF] %s : <empty len=0>\n", tag);
        return;
    }
    const unsigned char *p = (const unsigned char *)data;
    size_t show = len > 256 ? 256 : len;

    // 尝试 UTF-8 可读
    NSData *d = [NSData dataWithBytes:data length:len];
    NSString *s = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
    NSString *readable = (s && s.length) ? s : @"(非UTF8)";

    // hex
    NSMutableString *hex = [NSMutableString string];
    for (size_t i = 0; i < show; i++) [hex appendFormat:@"%02x", p[i]];

    sf_log("[SF] ==== %s (len=%zu) ====\n", tag, len);
    sf_log("[SF]   hex : %s%s\n", hex.UTF8String, (len > show) ? "..." : "");
    sf_log("[SF]   str : %s\n", readable.UTF8String);
}

// ---------- 原始函数指针 ----------
static unsigned char *(*orig_CC_MD5)(const void *, CC_LONG, unsigned char *);
static unsigned char *(*orig_CC_SHA1)(const void *, CC_LONG, unsigned char *);
static unsigned char *(*orig_CC_SHA224)(const void *, CC_LONG, unsigned char *);
static unsigned char *(*orig_CC_SHA256)(const void *, CC_LONG, unsigned char *);
static unsigned char *(*orig_CC_SHA384)(const void *, CC_LONG, unsigned char *);
static unsigned char *(*orig_CC_SHA512)(const void *, CC_LONG, unsigned char *);
static CCCryptorStatus (*orig_CCCrypt)(CCOperation, CCAlgorithm, CCOptions, const void *, size_t, const void *, const void *, size_t, void *, size_t, size_t *);
static int (*orig_CCKeyDerivationPBKDF)(CCPBKDFAlgorithm, const char *, size_t, const uint8_t *, size_t, CCPseudoRandomAlgorithm, unsigned, uint8_t *, size_t);
static void (*orig_CCHmac)(CCHmacAlgorithm, const void *, size_t, const void *, size_t, void *);

// SHA3 符号（iOS 13+ 才有，动态获取，不存在则跳过）
static unsigned char *(*orig_CC_SHA3_256)(const void *, CC_LONG, unsigned char *) = NULL;
static unsigned char *(*orig_CC_SHA3_384)(const void *, CC_LONG, unsigned char *) = NULL;
static unsigned char *(*orig_CC_SHA3_512)(const void *, CC_LONG, unsigned char *) = NULL;

// ---------- 替换实现 ----------
static unsigned char *my_CC_MD5(const void *data, CC_LONG len, unsigned char *md) {
    sf_dump("CC_MD5", data, len);
    return orig_CC_MD5(data, len, md);
}
static unsigned char *my_CC_SHA1(const void *data, CC_LONG len, unsigned char *md) {
    sf_dump("CC_SHA1", data, len);
    return orig_CC_SHA1(data, len, md);
}
static unsigned char *my_CC_SHA224(const void *data, CC_LONG len, unsigned char *md) {
    sf_dump("CC_SHA224", data, len);
    return orig_CC_SHA224(data, len, md);
}
static unsigned char *my_CC_SHA256(const void *data, CC_LONG len, unsigned char *md) {
    sf_dump("CC_SHA256", data, len);
    return orig_CC_SHA256(data, len, md);
}
static unsigned char *my_CC_SHA384(const void *data, CC_LONG len, unsigned char *md) {
    sf_dump("CC_SHA384", data, len);
    return orig_CC_SHA384(data, len, md);
}
static unsigned char *my_CC_SHA512(const void *data, CC_LONG len, unsigned char *md) {
    sf_dump("CC_SHA512", data, len);
    return orig_CC_SHA512(data, len, md);
}

static unsigned char *my_CC_SHA3_256(const void *data, CC_LONG len, unsigned char *md) {
    sf_dump("CC_SHA3_256", data, len);
    return orig_CC_SHA3_256(data, len, md);
}
static unsigned char *my_CC_SHA3_384(const void *data, CC_LONG len, unsigned char *md) {
    sf_dump("CC_SHA3_384", data, len);
    return orig_CC_SHA3_384(data, len, md);
}
static unsigned char *my_CC_SHA3_512(const void *data, CC_LONG len, unsigned char *md) {
    sf_dump("CC_SHA3_512", data, len);
    return orig_CC_SHA3_512(data, len, md);
}

static CCCryptorStatus my_CCCrypt(CCOperation op, CCAlgorithm alg, CCOptions opt,
    const void *key, size_t keyLen, const void *iv,
    const void *dataIn, size_t dataInLen,
    void *dataOut, size_t dataOutAvail, size_t *dataOutMoved) {
    sf_log("[SF] ==== CCCrypt (AES/DES) op=%d alg=%d ====\n", op, alg);
    sf_dump("CCCrypt.key", key, keyLen);
    if (iv) sf_dump("CCCrypt.iv", iv, (alg == kCCAlgorithmAES128) ? kCCBlockSizeAES128 : 8);
    sf_dump("CCCrypt.dataIn", dataIn, dataInLen);
    return orig_CCCrypt(op, alg, opt, key, keyLen, iv, dataIn, dataInLen, dataOut, dataOutAvail, dataOutMoved);
}

static int my_CCKeyDerivationPBKDF(CCPBKDFAlgorithm alg, const char *password, size_t pwLen,
    const uint8_t *salt, size_t saltLen, CCPseudoRandomAlgorithm prf, unsigned rounds,
    uint8_t *derivedKey, size_t derivedKeyLen) {
    sf_log("[SF] ==== PBKDF alg=%d prf=%d rounds=%u ====\n", alg, prf, rounds);
    sf_dump("PBKDF.password", password, pwLen);
    sf_dump("PBKDF.salt", salt, saltLen);   // <-- 盐很可能在这里
    return orig_CCKeyDerivationPBKDF(alg, password, pwLen, salt, saltLen, prf, rounds, derivedKey, derivedKeyLen);
}

static void my_CCHmac(CCHmacAlgorithm alg, const void *key, size_t keyLen, const void *data, size_t dataLen, void *out) {
    sf_log("[SF] ==== CCHmac alg=%d ====\n", alg);
    sf_dump("CCHmac.key", key, keyLen);
    sf_dump("CCHmac.data", data, dataLen);
    orig_CCHmac(alg, key, keyLen, data, dataLen, out);
}

// ---------- RN 模块调用 hook（顺丰是 React Native，能看到 encryptMD5 等方法名+参数） ----------
%hook RCTModuleMethod
- (id)invokeWithBridge:(id)bridge module:(id)module arguments:(NSArray *)arguments {
    NSString *jsName = [self valueForKey:@"JSMethodName"];   // 私有 ivar，可能拿到方法名
    sf_log("[SF] ==== RCTModuleMethod.invoke ====\n");
    sf_log("[SF]   method : %s\n", jsName ? jsName.UTF8String : "(unknown)");
    sf_log("[SF]   module : %s\n", [[module class] description].UTF8String);
    if (arguments) {
        for (NSUInteger i = 0; i < arguments.count; i++) {
            id a = arguments[i];
            sf_log("[SF]   arg[%lu] : %s\n", (unsigned long)i, [[a description] UTF8String]);
        }
    }
    return %orig(bridge, module, arguments);
}
%end

// ---------- 运行时扫描：列出 App 内可疑的加密类/方法（帮助定位 iOS 类名） ----------
static void sf_scan_classes(void) {
    NSString *appImage = NSBundle.mainBundle.executablePath;
    sf_log("[SF] ===== 扫描主 App 内的加密相关类/方法 =====\n");
    int clsCount = objc_getClassList(NULL, 0);
    Class *classes = (Class *)malloc(sizeof(Class) * clsCount);
    objc_getClassList(classes, clsCount);
    int hit = 0;
    for (int i = 0; i < clsCount && hit < 60; i++) {
        const char *img = class_getImageName(classes[i]);
        if (!img || strcmp(img, appImage.UTF8String) != 0) continue;   // 只关注主 App 镜像
        const char *cname = class_getName(classes[i]);
        if (strstr(cname, "Key") || strstr(cname, "Encrypt") || strstr(cname, "MD5") ||
            strstr(cname, "SHA") || strstr(cname, "Salt") || strstr(cname, "Token") ||
            strstr(cname, "Crypt") || strstr(cname, "Sign") || strstr(cname, "Cipher")) {
            sf_log("[SF]   class: %s\n", cname);
            unsigned int mCount = 0;
            Method *methods = class_copyMethodList(classes[i], &mCount);
            for (unsigned int j = 0; j < mCount; j++) {
                sf_log("[SF]     - %s\n", sel_getName(method_getName(methods[j])));
            }
            free(methods);
            hit++;
        }
    }
    free(classes);
    sf_log("[SF] ===== 扫描结束 =====\n");
}

// ---------- 构造函数 ----------
%ctor {
    sf_open_log();
    sf_log("\n[SF] ============ SFHook loaded ============\n");

    // 1. hook CommonCrypto（确定的符号）
    struct rebinding rb[] = {
        {"CC_MD5",    (void *)my_CC_MD5,    (void **)&orig_CC_MD5},
        {"CC_SHA1",   (void *)my_CC_SHA1,   (void **)&orig_CC_SHA1},
        {"CC_SHA224", (void *)my_CC_SHA224, (void **)&orig_CC_SHA224},
        {"CC_SHA256", (void *)my_CC_SHA256, (void **)&orig_CC_SHA256},
        {"CC_SHA384", (void *)my_CC_SHA384, (void **)&orig_CC_SHA384},
        {"CC_SHA512", (void *)my_CC_SHA512, (void **)&orig_CC_SHA512},
        {"CCCrypt",   (void *)my_CCCrypt,   (void **)&orig_CCCrypt},
        {"CCKeyDerivationPBKDF", (void *)my_CCKeyDerivationPBKDF, (void **)&orig_CCKeyDerivationPBKDF},
        {"CCHmac",    (void *)my_CCHmac,    (void **)&orig_CCHmac},
    };
    rebind_symbols(rb, sizeof(rb) / sizeof(rb[0]));

    // 2. hook SHA3（动态符号，不存在则跳过）
    orig_CC_SHA3_256 = (unsigned char *(*)(const void *, CC_LONG, unsigned char *))dlsym(RTLD_DEFAULT, "CC_SHA3_256");
    orig_CC_SHA3_384 = (unsigned char *(*)(const void *, CC_LONG, unsigned char *))dlsym(RTLD_DEFAULT, "CC_SHA3_384");
    orig_CC_SHA3_512 = (unsigned char *(*)(const void *, CC_LONG, unsigned char *))dlsym(RTLD_DEFAULT, "CC_SHA3_512");
    if (orig_CC_SHA3_256) {
        struct rebinding rb3[] = {
            {"CC_SHA3_256", (void *)my_CC_SHA3_256, (void **)&orig_CC_SHA3_256},
            {"CC_SHA3_384", (void *)my_CC_SHA3_384, (void **)&orig_CC_SHA3_384},
            {"CC_SHA3_512", (void *)my_CC_SHA3_512, (void **)&orig_CC_SHA3_512},
        };
        rebind_symbols(rb3, sizeof(rb3) / sizeof(rb3[0]));
        sf_log("[SF] SHA3 hooked\n");
    } else {
        sf_log("[SF] SHA3 符号不存在（iOS < 13），跳过\n");
    }

    sf_log("[SF] CommonCrypto hook 完成，等待触发加密...\n");

    // 3. 扫描可疑类（延迟 1 秒，等类加载）
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        sf_scan_classes();
    });
}
