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
#import <UIKit/UIKit.h>

#import <fcntl.h>
#import <unistd.h>
#import <stdio.h>
#import <stdarg.h>
#import <string.h>
#import <stdlib.h>
#import <dispatch/dispatch.h>

// ---------- 日志工具 ----------
// 同时写两个位置：
//   1) App 沙盒 Documents/sf_hook.log  —— 没越狱也能用爱思助手/iMazing 导出（主用）
//   2) /tmp/sf_hook.log               —— 有 Filza/SSH 的越狱环境直接看
static int sf_fd_doc = -1;
static int sf_fd_tmp = -1;

static void sf_open_log(void) {
    if (sf_fd_doc >= 0) return;
    NSArray *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    if (docs.count) {
        NSString *p = [docs[0] stringByAppendingPathComponent:@"sf_hook.log"];
        sf_fd_doc = open(p.UTF8String, O_WRONLY | O_CREAT | O_APPEND, 0644);
    }
    sf_fd_tmp = open("/tmp/sf_hook.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
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
    if (sf_fd_doc >= 0) write(sf_fd_doc, buf, n);
    if (sf_fd_tmp >= 0) write(sf_fd_tmp, buf, n);
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

// ---------- 弹窗显示（没越狱/没任何工具也能在屏幕上看结果） ----------
static int sf_alert_count = 0;

static void sf_alert(NSString *title, NSString *msg) {
    if (sf_alert_count >= 60) return;   // 最多弹 60 次
    sf_alert_count++;
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *win = nil;
        for (UIWindow *w in UIApplication.sharedApplication.windows) {
            if (w.isKeyWindow || w.windowLevel == UIWindowLevelNormal) { win = w; break; }
        }
        if (!win) return;
        UIViewController *vc = win.rootViewController;
        while (vc.presentedViewController) vc = vc.presentedViewController;
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:title
            message:msg preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [vc presentViewController:alert animated:YES completion:nil];
    });
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
    if (len > 8 && len < 800) {
        NSData *d = [NSData dataWithBytes:data length:len];
        NSString *s = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
        if (s && s.length > 8) {
            // sytToken 拼接串强特征：以 "CN" 开头（regionCode=CN + languageCode=sc）
            BOOL isSyt = [s hasPrefix:@"CN"] || [s hasPrefix:@"cn"];
            if (isSyt) {
                static int syt_shown = 0;
                if (syt_shown < 10) {
                    syt_shown++;
                    NSString *msg = s.length > 400 ? [[s substringToIndex:400] stringByAppendingString:@"…"] : s;
                    sf_alert([NSString stringWithFormat:@"★sytToken MD5输入(len=%d)", (int)len], msg);
                }
            } else {
                // 其他 MD5：过滤明显无关项后走配额弹窗
                if (![s hasPrefix:@"com.sf-express."] && ![s hasPrefix:@"file://"] &&
                    ![s hasSuffix:@".png"] && ![s hasSuffix:@".jpg"] && ![s hasSuffix:@".webp"]) {
                    NSString *msg = s.length > 280 ? [[s substringToIndex:280] stringByAppendingString:@"…"] : s;
                    sf_alert([NSString stringWithFormat:@"CC_MD5 输入(len=%d)", (int)len], msg);
                }
            }
        }
    }
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
// 显式声明为 NSObject 子类，否则 [self ...] 消息因前向声明而编译报错
@interface RCTModuleMethod : NSObject
@end

// 用 runtime 读 JS 方法名（ivar 名随 RN 版本变化，多候选兜底）
static NSString *sf_jsMethodName(RCTModuleMethod *selfObj) {
    const char *candidates[] = {"_JSMethodName", "JSMethodName", "_methodName", "_jsMethodName", "_selectorName"};
    for (int i = 0; i < (int)(sizeof(candidates) / sizeof(candidates[0])); i++) {
        Ivar ivar = class_getInstanceVariable([selfObj class], candidates[i]);
        if (ivar) {
            id v = object_getIvar(selfObj, ivar);
            if (v && [v isKindOfClass:[NSString class]]) return v;
        }
    }
    return nil;
}

%hook RCTModuleMethod
- (id)invokeWithBridge:(id)bridge module:(id)module arguments:(NSArray *)arguments {
    NSString *jsName = sf_jsMethodName(self);
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

// ---------- 抓请求头：直接看 sytToken / sign / token 头的值（最精准） ----------
%hook NSMutableURLRequest
- (void)setValue:(NSString *)value forHTTPHeaderField:(NSString *)field {
    if (value && value.length && field) {
        NSString *lf = [field lowercaseString];
        if ([lf containsString:@"token"] || [lf containsString:@"sign"] ||
            [lf containsString:@"syt"] || [lf containsString:@"auth"] ||
            [lf containsString:@"digest"] || [lf containsString:@"key"]) {
            sf_log("[SF] HEADER %@ = %@\n", field, value);
            NSString *v = value.length > 280 ? [value substringToIndex:280] : value;
            sf_alert([NSString stringWithFormat:@"请求头 %@", field], v);
        }
    }
    %orig(value, field);
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

    // 4. 启动确认弹窗（延迟 2 秒等 UI 起来，看到它 = 注入/hook 成功）
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        sf_alert(@"SFHook 已加载", @"注入成功，加密监控已开启。\n\n点几下首页/登录页触发请求，\n看到「CC_MD5 输入」弹窗即说明 hook 生效。");
    });
}
