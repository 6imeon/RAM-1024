/* SPDX-License-Identifier: MIT */
/* RAM-1024 tree leaves on the GPU (Metal), concurrently with CPU threads.
 * The GPU hashes chunks [0, g); CPU threads hash [g, n); the root is
 * computed on the CPU. Digest is identical to ram_hash / ram_hash_tree. */
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include <stdlib.h>
#include <string.h>

#include "ram1024.h"
#include "ram_constants.h"
#include "ram_metal_src.h"

#ifndef RAM_GPU_TG
#define RAM_GPU_TG 64
#endif

static id<MTLDevice> g_dev;
static id<MTLCommandQueue> g_queue;
static id<MTLComputePipelineState> g_pipe;
static id<MTLBuffer> g_rc;

static int gpu_setup(void)
{
    static dispatch_once_t once;
    static int ok;
    dispatch_once(&once, ^{
        @autoreleasepool {
            g_dev = MTLCreateSystemDefaultDevice();
            if (!g_dev) return;
            NSError *err = nil;
            MTLCompileOptions *opt = [MTLCompileOptions new];
            id<MTLLibrary> lib = [g_dev newLibraryWithSource:@(RAM_METAL_SRC)
                                                     options:opt error:&err];
            if (!lib) {
                NSLog(@"ram_gpu: compile failed: %@", err);
                return;
            }
            g_pipe = [g_dev newComputePipelineStateWithFunction:
                                [lib newFunctionWithName:@"ram_leaf"] error:&err];
            if (!g_pipe) return;
            g_queue = [g_dev newCommandQueue];
            g_rc = [g_dev newBufferWithBytes:RAM_RC length:sizeof RAM_RC
                                     options:MTLResourceStorageModeShared];
            ok = 1;
        }
    });
    return ok;
}

int ram_gpu_available(void) { return gpu_setup(); }

int ram_hash_gpu(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen,
                 int rounds, double gpu_share)
{
    if (ram_check_params(outlen, RAM_MODE_HASH, rounds)) return -1;
    if (inlen <= RAM_CHUNK || (rounds & 3) || !gpu_setup())
        return ram_hash_tree(out, outlen, in, inlen, rounds, 0);
    if (!(gpu_share >= 0 && gpu_share <= 1)) gpu_share = 0.7; /* also NaN; M3 Pro optimum */
    uint64_t nchunks = (inlen + RAM_CHUNK - 1) / RAM_CHUNK;
    uint64_t nfull = inlen / RAM_CHUNK;
    if (nfull == nchunks) nfull--;
    uint64_t g = (uint64_t)(gpu_share * (double)nfull);
    if (g > nfull) g = nfull;
    g &= ~1ULL; /* CPU part starts on a pair boundary */
    uint8_t *cvs = malloc(nchunks * RAM_CV);
    if (!cvs) return ram_hash_tree(out, outlen, in, inlen, rounds, 0);
    @autoreleasepool {
        id<MTLCommandBuffer> cb = nil;
        id<MTLBuffer> outb = nil;
        if (g) {
            /* Zero-copy when the caller's buffer is page aligned. */
            size_t glen = g * RAM_CHUNK, page = (size_t)getpagesize();
            id<MTLBuffer> inb;
            if (((uintptr_t)in % page) == 0 && glen % page == 0)
                inb = [g_dev newBufferWithBytesNoCopy:(void *)in length:glen
                                              options:MTLResourceStorageModeShared
                                          deallocator:nil];
            else
                inb = [g_dev newBufferWithBytes:in length:glen
                                        options:MTLResourceStorageModeShared];
            outb = [g_dev newBufferWithLength:g * RAM_CV
                                      options:MTLResourceStorageModeShared];
            if (!inb || !outb) { /* too large for a Metal buffer: CPU only */
                free(cvs);
                return ram_hash_tree(out, outlen, in, inlen, rounds, 0);
            }
            uint64_t prm[4] = {0,
                               RAM_VERSION_WORD | ((uint64_t)RAM_MODE_LEAF << 24) |
                                   ((uint64_t)rounds << 16),
                               g, (uint64_t)rounds};
            cb = [g_queue commandBuffer];
            id<MTLComputeCommandEncoder> enc = [cb computeCommandEncoder];
            [enc setComputePipelineState:g_pipe];
            [enc setBuffer:inb offset:0 atIndex:0];
            [enc setBuffer:outb offset:0 atIndex:1];
            [enc setBuffer:g_rc offset:0 atIndex:2];
            [enc setBytes:prm length:sizeof prm atIndex:3];
            NSUInteger tg = g_pipe.maxTotalThreadsPerThreadgroup;
            const char *env = getenv("RAM_GPU_TG"); /* tuning knob */
            long envv = env ? strtol(env, NULL, 10) : 0;
            NSUInteger want = envv > 0 && envv <= 1024 ? (NSUInteger)envv : RAM_GPU_TG;
            if (tg > want) tg = want;
            [enc dispatchThreads:MTLSizeMake(g, 1, 1)
                threadsPerThreadgroup:MTLSizeMake(tg, 1, 1)];
            [enc endEncoding];
            [cb commit];
        }
        ram_tree_leaves_cpu(in, inlen, g, nchunks, cvs, rounds, 0);
        if (cb) {
            [cb waitUntilCompleted];
            if (cb.status != MTLCommandBufferStatusCompleted) {
                ram_tree_leaves_cpu(in, inlen, 0, g, cvs, rounds, 0);
            } else {
                memcpy(cvs, outb.contents, g * RAM_CV);
            }
        }
    }
    ram_tree_root(out, outlen, cvs, nchunks, rounds);
    free(cvs);
    return 0;
}
