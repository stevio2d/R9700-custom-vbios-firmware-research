// Included only in the opt-in self-test build; never linked into the serving engine.
#include <stdexcept>

static void tp4_require(bool yes, const char* message) {
    if (!yes) throw std::runtime_error(message);
}

static uint64_t tp4_hash(const void* data, size_t bytes) {
    const uint8_t* p = (const uint8_t*)data;
    uint64_t h = 1469598103934665603ull;
    for (size_t i = 0; i < bytes; ++i) { h ^= p[i]; h *= 1099511628211ull; }
    return h;
}

static void* tp4_copy(const void* src, size_t bytes) {
    void* p = dalloc(bytes);
    tp4_require(p != nullptr, "device allocation failed");
    tp4_require(st_memcpy(p, src, bytes, hipMemcpyHostToDevice) == hipSuccess, "upload failed");
    return p;
}

template <class F> static void tp4_warm(F&& launch) {
    hipEvent_t begin, end;
    st_ev_create(&begin); st_ev_create(&end); st_ev_record(begin, nullptr);
    float ms = 0;
    for (int guard = 0; guard < 10000 && ms < 100; ++guard) {
        for (int i = 0; i < 8; ++i) launch();
        st_ev_record(end, nullptr); st_ev_sync(end); st_ev_elapsed(&ms, begin, end);
    }
    st_ev_destroy(begin); st_ev_destroy(end);
    tp4_require(ms >= 100, "GPU warmup did not complete");
}

// Source-plane values can be reconstructed independently of the stored layout.
static int tp4_code(int64_t expert, int64_t n, int64_t k) {
    return (int)(st_mix32((uint32_t)(expert * 100003 + n * 257 + k)) & 15u);
}
static uint8_t tp4_scale(int64_t expert, int64_t n, int64_t group64) {
    return (uint8_t)(0x28 + ((expert + n * 3 + group64 * 5) & 7));
}

static void tp4_protected(const Plugin& pl, int rank, int64_t E,
                         const std::vector<int32_t>& offsets, const std::vector<int32_t>& sorted,
                         const std::vector<int>& owner) {
    const int64_t M = 4, top = 10, Tr = M * top, np = 512 - E;
    const int64_t width = rank < 2 ? 192 : 128;
    const RadKernelInfo* row = find(pl, "moe_gemm_bf16");
    tp4_require(row && row->scratch, "protected BF16 row absent");
    tp4_require(offsets[(size_t)E] < Tr, "fixture has no protected rows");
    for (bool down : {false, true}) {
        const int64_t N = down ? 2560 : 2 * width, K = down ? width : 2560, AR = down ? Tr : M;
        std::vector<uint16_t> activation((size_t)(AR * K), 0), weights((size_t)(np * N * K));
        auto amp = [](int64_t a) { return (float)(1 + a % 4) / 4; };
        auto coefficient = [](int64_t e, int64_t n) { return (float)(1 + (e * 13 + n * 3) % 63) / 64; };
        for (int64_t a = 0; a < AR; ++a) activation[(size_t)(a * K + K - 1)] = h_to_bf16(amp(a));
        for (int64_t e = 0; e < np; ++e) for (int64_t n = 0; n < N; ++n)
            std::fill_n(weights.data() + ((np - 1 - e) * N + n) * K, (size_t)K,
                        h_to_bf16(coefficient(e, n)));
        void* dw = tp4_copy(weights.data(), weights.size() * 2);
        std::vector<const void*> table((size_t)np);
        for (int64_t e = 0; e < np; ++e) table[(size_t)e] = (const uint16_t*)dw + (np - 1 - e) * N * K;
        std::vector<uint16_t> junk((size_t)(Tr * N), 0x3eab), expected = junk, got(junk.size());
        for (int64_t i = offsets[(size_t)E]; i < Tr; ++i) {
            const int64_t e = owner[(size_t)i] - E;
            tp4_require(e >= 0 && e < np, "protected row ownership invalid");
            const int64_t ai = down ? i : sorted[(size_t)i] / top;
            for (int64_t n = 0; n < N; ++n)
                expected[(size_t)(i * N + n)] = h_to_bf16(coefficient(e, n) * amp(ai));
        }
        void* dy = tp4_copy(junk.data(), junk.size() * 2);
        std::vector<RadTensor> tensors = {
            T(tp4_copy(activation.data(), activation.size() * 2), RAD_BF16, {AR, K}),
            T(tp4_copy(table.data(), table.size() * sizeof(void*)), RAD_BF16, {np, N, K}),
            T(tp4_copy(sorted.data(), sorted.size() * 4), RAD_I32, {Tr}),
            T(tp4_copy(offsets.data() + E, ((size_t)np + 1) * 4), RAD_I32, {np + 1}),
            T(dy, RAD_BF16, {Tr, N}) };
        tensors[1].stride[0] = 0;
        std::vector<RadParam> params = { PI("M", M), PI("N", N), PI("K", K), PI("n_expert", np),
            PI("top_k", top), PS("a_order", down ? "sorted" : "token"), PS("dtype", "bf16") };
        RadArgs a{}; a.t = tensors.data(); a.n_t = (int)tensors.size();
        a.p = params.data(); a.n_p = (int)params.size();
        a.scratch_bytes = std::max<int64_t>(row->scratch(&a), (1 + 2 * (np + Tr / 16 + 2)) * 4);
        a.scratch = dalloc((size_t)a.scratch_bytes);
        tp4_require(a.scratch, "protected scratch allocation failed");
        for (int form : {0, 1, 2, 3}) {
            pl.pin_moe(form);
            st_memcpy(dy, junk.data(), junk.size() * 2, hipMemcpyHostToDevice);
            tp4_require(row->launch(&a, nullptr) == RAD_OK && st_stream_sync(nullptr) == hipSuccess,
                        "protected BF16 launch failed");
            st_memcpy(got.data(), dy, got.size() * 2, hipMemcpyDeviceToHost);
            tp4_require(got == expected, "protected BF16 ownership or untouched prefix disagreed");
            std::printf("TP4_PROTECTED rank=%d regular=%lld protected=%lld projection=%s form=%d oracle=pass prefix=pass\n",
                        rank, (long long)E, (long long)np, down ? "down" : "gate_up", form);
        }
        pl.pin_moe(0); dfree_all();
    }
}

static void tp4_moe(const Plugin& pl, int64_t M, int64_t E, int rank, int iters) {
    tp4_require(M > 0 && M <= 2048 && (E == 512 || E == 510 || E == 508) &&
                rank >= 0 && rank < 4 && iters > 0 && iters <= 1000, "invalid MoE fixture arguments");
    const RadKernelInfo* row = find(pl, "moe_gemm_w4a8_mod4");
    tp4_require(row && row->layout && row->relayout && pl.pin_moe && pl.pin_fk &&
                pl.pin_ddec && pl.pin_dtile && row->scratch, "TP4 MoE row or pin hooks absent");
    tp4_require(st_set_device(rank) == hipSuccess, "rank device unavailable");
    g_cold = 256ll << 20; // active decode experts fit in LLC; the serving graph streams layers
    constexpr int top = 10, total = 512;
    const int64_t Tr = M * top, protected_count = total - E;
    // Full top-10 distinct routing, stable sort, protected experts after the regular ones.
    // Original IDs are deliberately interspersed, then compacted, as the graph does.
    std::vector<int> original, protected_ids;
    for (int e = 0; e < total; ++e) {
        const bool prot = protected_count && (e == 1 || e == 510 ||
                          (protected_count == 4 && (e == 129 || e == 388)));
        (prot ? protected_ids : original).push_back(e);
    }
    tp4_require((int64_t)original.size() == E, "protected-ID compaction failed");
    std::vector<int32_t> ids((size_t)Tr), offsets(total + 1, 0), sorted((size_t)Tr);
    std::mt19937_64 rng(9700 + (uint64_t)M);
    std::vector<double> popularity(total);
    std::normal_distribution<double> normal(0.0, 0.8);
    for (double& p : popularity) p = normal(rng);
    std::vector<std::pair<double, int>> scores(total);
    for (int64_t t = 0; t < M; ++t) {
        for (int e = 0; e < total; ++e) {
            const double u = ((double)(rng() >> 11) + .5) / 9007199254740992.0;
            scores[(size_t)e] = { popularity[(size_t)e] - std::log(-std::log(u)), e };
        }
        std::partial_sort(scores.begin(), scores.begin() + top, scores.end(),
                          [](const auto& a, const auto& b) { return a.first > b.first; });
        for (int j = 0; j < top; ++j) ids[(size_t)(t * top + j)] = scores[(size_t)j].second;
    }
    // Ensure every small correctness fixture actually exercises each protected expert.
    for (size_t j = 0; j < protected_ids.size(); ++j) {
        const int wanted = protected_ids[j];
        auto at = std::find(ids.begin(), ids.begin() + top, wanted);
        if (at == ids.begin() + top) ids[j] = wanted;
        else std::swap(ids[j], *at);
    }
    for (int q = 0; q < 4; ++q) {
        const int wanted = original[(size_t)q];
        const size_t slot = protected_ids.size() + (size_t)q;
        auto at = std::find(ids.begin(), ids.begin() + top, wanted);
        if (at == ids.begin() + top) ids[slot] = wanted;
        else std::swap(ids[slot], *at);
    }
    std::vector<int> compact(total);
    for (int64_t e = 0; e < E; ++e) compact[(size_t)original[(size_t)e]] = (int)e;
    for (size_t j = 0; j < protected_ids.size(); ++j)
        compact[(size_t)protected_ids[j]] = (int)(E + j);
    for (int32_t& e : ids) { e = compact[(size_t)e]; ++offsets[(size_t)e + 1]; }
    for (int e = 0; e < total; ++e) offsets[(size_t)e + 1] += offsets[(size_t)e];
    auto next = offsets;
    for (int64_t f = 0; f < Tr; ++f) sorted[(size_t)next[(size_t)ids[(size_t)f]]++] = (int32_t)f;
    std::vector<int> owner((size_t)Tr, -1);
    for (int e = 0; e < total; ++e)
        for (int32_t i = offsets[(size_t)e]; i < offsets[(size_t)e + 1]; ++i) owner[(size_t)i] = e;
    for (int64_t t = 0; t < M; ++t) {
        std::vector<int32_t> check(ids.begin() + t * top, ids.begin() + (t + 1) * top);
        std::sort(check.begin(), check.end());
        tp4_require(std::adjacent_find(check.begin(), check.end()) == check.end(), "duplicate top-k expert");
    }
    const uint64_t routing_hash = tp4_hash(sorted.data(), sorted.size() * 4);
    struct Variant { const char* name; int form, fk, down, tile; };
    for (bool down : { false, true }) {
        const int parts = down ? 1 : 2;
        const int64_t N = down ? 2560 : 512, K = down ? 256 : 2560;
        const int64_t AR = down ? Tr : M;
        int64_t nq[4], kq[4], counts[4];
        for (int q = 0; q < 4; ++q) {
            nq[q] = down ? 2560 : q == rank ? 512 : 256;
            kq[q] = down ? (q == rank ? 256 : 128) : 2560;
            counts[q] = (E + 3 - q) / 4;
        }
        std::vector<RadParam> params = {
            PI("M", M), PI("N", nq[0]), PI("K", kq[0]),
            PI("N_1", nq[1]), PI("K_1", kq[1]), PI("N_2", nq[2]), PI("K_2", kq[2]),
            PI("N_3", nq[3]), PI("K_3", kq[3]), PI("parts", parts), PI("n_expert", E),
            PI("top_k", top), PI("group", 128), PS("a_order", down ? "sorted" : "token"),
            PS("dtype", "w4nl64a8h") };
        RadTensor weights[4], scales[4];
        for (int q = 0; q < 4; ++q) {
            const int64_t nc = nq[q], kc = kq[q];
            const size_t wb = (size_t)(nc * kc / 2), sb = (size_t)(nc * kc / 64);
            std::vector<uint8_t> all_w((size_t)counts[q] * wb), all_s((size_t)counts[q] * sb);
            for (int64_t x = 0; x < counts[q]; ++x) {
                const int original_id = original[(size_t)(4 * x + q)];
                Planes p;
                rad_enc_clear(&p.enc);
                rad_enc_copy_str(p.enc.scheme, "affine");
                rad_enc_copy_str(p.enc.transform, "fwht128");
                rad_enc_add_plane(&p.enc, "codes", RAD_U4, 1, 1);
                rad_enc_add_plane(&p.enc, "scale", RAD_F8E4M3, 1, 64);
                rad_enc_add_plane(&p.enc, "scale.1", RAD_F32, 0, 0);
                rad_enc_add_table(&p.enc, "table", RAD_F32, 1, 16);
                p.size(nc, kc);
                std::memcpy(p.data[2].data(), &kW4G64Scale, 4);
                std::memcpy(p.data[3].data(), kW4nlTable, sizeof(kW4nlTable));
                for (int64_t n = 0; n < nc; ++n) {
                    for (int64_t k = 0; k < kc; k += 2)
                        p.data[0][(size_t)(n * kc / 2 + k / 2)] = (uint8_t)(
                            tp4_code(original_id, n, k) | (tp4_code(original_id, n, k + 1) << 4));
                    for (int64_t g = 0; g < kc / 64; ++g)
                        p.data[1][(size_t)(n * kc / 64 + g)] = tp4_scale(original_id, n, g);
                }
                std::vector<uint8_t> w, s;
                const int operand = q ? 4 + 2 * q : 2;
                tp4_require(stored(row, params, operand, p, {"codes", "table"}, &w) == RAD_OK &&
                            stored(row, params, operand + 1, p, {"scale", "scale.1"}, &s) == RAD_OK,
                            "four-class relayout failed");
                tp4_require(w.size() == wb && s.size() == sb, "unexpected stored plane size");
                const size_t slot = (size_t)(counts[q] - 1 - x); // permuted physical tables
                std::memcpy(all_w.data() + slot * wb, w.data(), wb);
                std::memcpy(all_s.data() + slot * sb, s.data(), sb);
            }
            void* dw = tp4_copy(all_w.data(), all_w.size());
            void* ds = tp4_copy(all_s.data(), all_s.size());
            std::vector<const void*> wt((size_t)counts[q]), st((size_t)counts[q]);
            for (int64_t x = 0; x < counts[q]; ++x) {
                const size_t slot = (size_t)(counts[q] - 1 - x);
                wt[(size_t)x] = (const uint8_t*)dw + slot * wb;
                st[(size_t)x] = (const uint8_t*)ds + slot * sb;
            }
            weights[q] = T(tp4_copy(wt.data(), wt.size() * sizeof(void*)), R4D_DT_MOEW4,
                           {counts[q], nc, kc});
            scales[q] = T(tp4_copy(st.data(), st.size() * sizeof(void*)), RAD_F8E4M3,
                          {counts[q], nc, kc / 64});
            weights[q].stride[0] = scales[q].stride[0] = 0;
        }
        std::vector<uint8_t> activation((size_t)(AR * K), 0);
        std::vector<int64_t> active_k((size_t)AR);
        for (int64_t a = 0; a < AR; ++a) {
            const int e = down ? owner[(size_t)a] : 0;
            const int64_t extent = down && e < E ? kq[e % 4] : K;
            active_k[(size_t)a] = (a & 1) ? extent - 1 : 0;
            activation[(size_t)(a * K + active_k[(size_t)a])] = 0x38; // exactly 1
            if (down && e < E)
                for (int64_t k = extent; k < K; ++k) activation[(size_t)(a * K + k)] = 0x38;
        }
        std::vector<float> asc((size_t)(AR * K / 128), 1.0f);
        void* da = tp4_copy(activation.data(), activation.size());
        void* das = tp4_copy(asc.data(), asc.size() * 4);
        std::vector<uint16_t> junk((size_t)(Tr * N), 0x7f7f), expected(junk.size(), 0), got(junk.size());
        void* dy = tp4_copy(junk.data(), junk.size() * 2);
        void* dsort = tp4_copy(sorted.data(), sorted.size() * 4);
        // The regular op sees E+1 offsets, and must zero every protected trailing row.
        void* doff = tp4_copy(offsets.data(), ((size_t)E + 1) * 4);
        std::vector<RadTensor> tensors = {
            T(da, RAD_F8E4M3, {AR, K}), T(das, RAD_F32, {AR, K / 128}), weights[0], scales[0],
            T(dsort, RAD_I32, {Tr}), T(doff, RAD_I32, {E + 1}), weights[1], scales[1],
            weights[2], scales[2], weights[3], scales[3], T(dy, RAD_BF16, {Tr, N}) };
        RadArgs a{};
        a.t = tensors.data(); a.n_t = (int)tensors.size(); a.p = params.data(); a.n_p = (int)params.size();
        const int64_t scratch = std::max<int64_t>(row->scratch(&a), (1 + 2 * (E + Tr / 16 + 2)) * 4);
        a.scratch = dalloc((size_t)scratch); a.scratch_bytes = scratch;
        tp4_require(a.scratch, "map allocation failed");
        for (int64_t i = 0; i < Tr; ++i) {
            const int e = owner[(size_t)i];
            if (e >= E) continue;
            const int q = e % 4;
            const int64_t ai = down ? i : sorted[(size_t)i] / top;
            const int64_t k = active_k[(size_t)ai], width = nq[q] / parts;
            for (int64_t n = 0; n < N; ++n) {
                const int64_t part = n / (N / parts), j = n % (N / parts);
                if (j >= width) continue;
                const int64_t wr = part * width + j;
                const int oe = original[(size_t)e];
                const float value = kW4nlTable[tp4_code(oe, wr, k)] *
                                    h_e4m3(tp4_scale(oe, wr, k / 64)) * kW4G64Scale;
                expected[(size_t)(i * N + n)] = h_to_bf16(value);
            }
        }
        pl.pin_moe(0); pl.pin_fk(0); pl.pin_ddec(0); pl.pin_dtile(0);
        tp4_require(row->launch(&a, nullptr) == RAD_OK && st_stream_sync(nullptr) == hipSuccess,
                    "sparse oracle launch failed");
        st_memcpy(got.data(), dy, got.size() * 2, hipMemcpyDeviceToHost);
        tp4_require(got == expected, "independent expert ownership/K/padding oracle disagreed");
        // Dense finite E4M3 values for timing: traffic is not a one-hot special case.
        for (size_t i = 0; i < activation.size(); ++i)
            activation[i] = (uint8_t)(8 + st_mix32((uint32_t)i ^ 0x9700u) % 111) |
                            (uint8_t)((i & 1) ? 0x80 : 0);
        std::fill(asc.begin(), asc.end(), 0.013f);
        st_memcpy(da, activation.data(), activation.size(), hipMemcpyHostToDevice);
        st_memcpy(das, asc.data(), asc.size() * 4, hipMemcpyHostToDevice);
        std::vector<Variant> variants = {
            {"rule", 0, 0, 0, 0}, {"aligned", 1, 0, 0, 0},
            {"uniform", 3, 0, 0, 0}, {"tile_run_fk128", 2, 1, -1, 0} };
        if (!down) variants.push_back({"tile_run_fk256", 2, 2, -1, 0});
        else {
            for (int g : {1, 2, 4, 8}) variants.push_back({"down_group", 2, 0, g, 0});
            variants.push_back({"aligned128", 1, 0, 0, 1});
            variants.push_back({"aligned256", 1, 0, 0, 2});
        }
        std::vector<uint16_t> reference;
        for (size_t vi = 0; vi < variants.size(); ++vi) {
            const Variant& v = variants[vi];
            pl.pin_moe(v.form); pl.pin_fk(v.fk); pl.pin_ddec(v.down); pl.pin_dtile(v.tile);
            st_memcpy(dy, junk.data(), junk.size() * 2, hipMemcpyHostToDevice);
            auto launch = [&]() { tp4_require(row->launch(&a, nullptr) == RAD_OK, "variant launch refused"); };
            launch(); tp4_require(st_stream_sync(nullptr) == hipSuccess, "variant failed");
            st_memcpy(got.data(), dy, got.size() * 2, hipMemcpyDeviceToHost);
            if (vi == 0) reference = got;
            tp4_require(got == reference, "dense variant differs byte for byte from stock rule");
            tp4_warm(launch);
            const double us = st_time_us([&](int) { launch(); }, iters, nullptr);
            st_memcpy(got.data(), dy, got.size() * 2, hipMemcpyDeviceToHost);
            tp4_require(got == reference && std::isfinite(us) && us > 0, "replay or timing failed");
            std::printf("TP4_MOE M=%lld E=%lld rank=%d projection=%s variant=%s group=%d us=%.6f hash=%llu routing=%llu oracle=pass bytes=pass\n",
                (long long)M, (long long)E, rank, down ? "down" : "gate_up", v.name, v.down,
                us, (unsigned long long)tp4_hash(got.data(), got.size() * 2),
                (unsigned long long)routing_hash);
            std::fflush(stdout);
        }
        pl.pin_moe(0); pl.pin_fk(0); pl.pin_ddec(0); pl.pin_dtile(0);
        dfree_all();
    }
    if (protected_count && M == 4) {
        tp4_protected(pl, rank, E, offsets, sorted, owner);
    }
}

static int g_tp4_ar_threads = 256;
static int g_tp4_ar_ready[4]{};

// Every rank publishes readiness before peers may initialize or launch a collective.
// The second barrier prevents the next phase overwriting a value still being read.
static bool tp4_ar_agree(Ar8Perf* t, int rc) {
    g_tp4_ar_ready[t->rank] = rc;
    t->bar->wait();
    bool good = true;
    for (int x : g_tp4_ar_ready) good = good && x == RAD_OK;
    t->bar->wait();
    return good;
}

// After a rendezvous launch, cleanup can itself wait for a missing peer. Fail the
// entire test process on any enqueue/runtime error; the independent supervisor
// retains the log and exit code. It never resets a GPU or restarts this test.
[[noreturn]] static void tp4_ar_abort(int rank, const char* stage, int rc) {
    std::fprintf(stderr, "TP4_AR_FAIL rank=%d stage=%s rc=%d\n", rank, stage, rc);
    std::fflush(stderr);
    std::_Exit(1);
}

static void tp4_ar_worker(Ar8Perf* t) {
    const size_t ncfg = t->sizes.size() * t->rows.size() * t->nbs.size();
    t->rc.assign(ncfg, RAD_E_STATE); t->bad.assign(ncfg, 0); t->period.assign(ncfg, 0);
    const int64_t most = *std::max_element(t->sizes.begin(), t->sizes.end());
    void *input = nullptr, *output = nullptr;
    hipEvent_t begin = nullptr, end = nullptr;
    std::vector<void*> instances(t->rows.size(), nullptr);
    auto cleanup = [&]() {
        for (size_t j = 0; j < instances.size(); ++j)
            if (instances[j]) t->rows[j]->fini(instances[j]);
        if (input && hipFree(input) != hipSuccess) t->rc_init = RAD_E_DEVICE;
        if (output && hipFree(output) != hipSuccess) t->rc_init = RAD_E_DEVICE;
        if (begin && hipEventDestroy(begin) != hipSuccess) t->rc_init = RAD_E_DEVICE;
        if (end && hipEventDestroy(end) != hipSuccess) t->rc_init = RAD_E_DEVICE;
    };
    int ready = hipSetDevice(t->dev) == hipSuccess ? RAD_OK : RAD_E_DEVICE;
    if (ready == RAD_OK && (hipMalloc(&input, (size_t)most * 2) != hipSuccess ||
        hipMalloc(&output, (size_t)most * 2) != hipSuccess ||
        hipEventCreate(&begin) != hipSuccess || hipEventCreate(&end) != hipSuccess))
        ready = RAD_E_NOMEM;
    if (!tp4_ar_agree(t, ready)) { t->rc_init = RAD_E_DEVICE; cleanup(); return; }
    std::vector<RadParam> init = { PI("world_size", 4), PI("numel", most),
                                  PS("dtype", "bf16"), PI("exact", 1) };
    for (size_t j = 0; j < t->rows.size(); ++j) {
        ready = t->rows[j]->init(init.data(), (int)init.size(), t->rank, 4, &instances[j]);
        // Failures inside plugin initialization rendezvous are bounded externally.
        if (!tp4_ar_agree(t, ready)) { t->rc_init = RAD_E_DEVICE; cleanup(); return; }
    }
    std::vector<uint16_t> h((size_t)most), want((size_t)most), got((size_t)most);
    auto checked = [&](hipError_t rc, const char* stage) {
        if (rc != hipSuccess) tp4_ar_abort(t->rank, stage, (int)rc);
    };
    size_t cfg = 0;
    for (int64_t n : t->sizes) for (size_t j = 0; j < t->rows.size(); ++j)
    for (int nb : t->nbs) {
        std::vector<RadParam> params = { PI("world_size", 4), PI("numel", n), PS("dtype", "bf16"),
            PI("exact", 1), PI("nthreads", g_tp4_ar_threads), PI("drain", 3), PI("acq", 0) };
        if (nb) params.push_back(PI("nblocks", nb));
        RadTensor tensors[2] = {T(input, RAD_BF16, {n}), T(output, RAD_BF16, {n})};
        RadArgs a{};
        a.t = tensors; a.n_t = 2; a.p = params.data(); a.n_p = (int)params.size();
        a.rank = t->rank; a.world_size = 4; a.instance = instances[j];
        auto pattern = [&](bool negative) {
            for (int64_t i = 0; i < n; ++i) {
                float sum = 0;
                for (int r = 0; r < 4; ++r) {
                    const float value = h_bf16(h_to_bf16(ar_pattern_value(r, i)));
                    sum += negative ? -value : value;
                }
                const float value = h_bf16(h_to_bf16(ar_pattern_value(t->rank, i)));
                h[(size_t)i] = h_to_bf16(negative ? -value : value);
                want[(size_t)i] = h_to_bf16(sum);
            }
            checked(hipMemcpy(input, h.data(), (size_t)n * 2, hipMemcpyHostToDevice), "input_upload");
            checked(hipMemset(output, 0xa5, (size_t)n * 2), "output_poison");
            tp4_ar_agree(t, RAD_OK);
        };
        auto launch = [&]() {
            const int rc = t->rows[j]->launch(&a, nullptr);
            if (rc != RAD_OK) tp4_ar_abort(t->rank, "launch", rc);
        };
        auto verify = [&]() {
            checked(hipStreamSynchronize(nullptr), "synchronize");
            checked(hipMemcpy(got.data(), output, (size_t)n * 2, hipMemcpyDeviceToHost), "readback");
            for (int64_t i = 0; i < n; ++i) t->bad[cfg] += got[(size_t)i] != want[(size_t)i];
            tp4_ar_agree(t, RAD_OK);
        };
        pattern(false); launch(); verify();
        for (int i = 0; i < std::max(t->iters, 100); ++i) launch();
        checked(hipStreamSynchronize(nullptr), "warmup_synchronize");
        tp4_ar_agree(t, RAD_OK);
        checked(hipMemset(output, 0xa5, (size_t)n * 2), "timed_output_poison");
        tp4_ar_agree(t, RAD_OK);
        checked(hipEventRecord(begin, nullptr), "event_begin");
        for (int i = 0; i < t->iters; ++i) launch();
        checked(hipEventRecord(end, nullptr), "event_end");
        checked(hipEventSynchronize(end), "event_synchronize");
        float ms = 0;
        checked(hipEventElapsedTime(&ms, begin, end), "elapsed");
        t->period[cfg] = ms / t->iters;
        verify();
        // Change values after timing: stale replay must not pass a constant-input oracle.
        pattern(true); launch(); verify();
        t->rc[cfg] = RAD_OK;
        ++cfg;
    }
    cleanup();
}

static void tp4_ar(const Plugin& pl, int iters) {
    tp4_require(iters >= 2 && iters <= 1000, "invalid collective iteration count");
    int nd = 0;
    tp4_require(hipGetDeviceCount(&nd) == hipSuccess && nd == 4, "exactly four visible GPUs required");
    for (int d = 0; d < 4; ++d) {
        hipDeviceProp_t p{};
        tp4_require(hipGetDeviceProperties(&p, d) == hipSuccess &&
                    !std::strncmp(p.gcnArchName, "gfx1201", 7), "native gfx1201 GPUs required");
    }
    const RadKernelInfo* one = find(pl, "ar_oneshot_4rank_exact");
    const RadKernelInfo* two = find(pl, "ar_twoshot_4rank_exact");
    tp4_require(one && two, "four-rank exact collective rows absent");
    const std::vector<int64_t> sizes = {2560, 10240, 81920, 327680, 524288, 524352, 5242880};
    const std::vector<int> blocks = {0, 4, 8, 16, 32};
    for (int nt : {64, 128, 256, 512}) {
        g_tp4_ar_threads = nt;
        StBarrier bar(4);
        std::vector<Ar8Perf> workers(4);
        std::vector<std::thread> threads;
        for (int rank = 0; rank < 4; ++rank) {
            Ar8Perf& w = workers[(size_t)rank];
            w.rank = w.dev = rank; w.world = 4; w.iters = iters; w.dtype = "bf16";
            w.sizes = sizes; w.rows = {one, two}; w.ks = {0, -1}; w.nbs = blocks; w.bar = &bar;
            threads.emplace_back(tp4_ar_worker, &w);
        }
        for (auto& t : threads) t.join();
        for (const auto& w : workers) tp4_require(w.rc_init == RAD_OK, "collective init failed");
        size_t cfg = 0;
        for (int64_t size : sizes) for (int row = 0; row < 2; ++row) for (int nb : blocks) {
            double us = 0;
            for (const auto& w : workers) {
                tp4_require(w.rc[cfg] == RAD_OK && w.bad[cfg] == 0, "collective oracle/replay failed");
                us = std::max(us, (double)w.period[cfg] * 1000);
            }
            tp4_require(std::isfinite(us) && us > 0, "invalid collective time");
            std::printf("TP4_AR numel=%lld row=%s blocks=%d threads=%d us=%.6f oracle=pass replay=pass\n",
                        (long long)size, row ? "two" : "one", nb, nt, us);
            ++cfg;
        }
        std::fflush(stdout);
    }
}

static void tp4_gdn(const Plugin& candidate, const char* stock_path, int iters,
                    int H = 12, int Hg = 4, int sequences = 1) {
    tp4_require(iters >= 2 && iters <= 1000, "invalid GDN iteration count");
    Plugin stock;
    tp4_require(load(&stock, stock_path), "stock plugin load failed");
    const char* name = "gdn_chunk_scan_k128_v128_c64_bf16";
    const RadKernelInfo* rows[2] = {find(stock, name), find(candidate, name)};
    tp4_require(rows[0] && rows[1], "GDN scan row absent");
    constexpr int K = 128, V = 128, C = 64;
    for (int length : {65, 75, 81, 200, 2048}) for (bool half : {false, true})
    for (bool decay : {false, true}) {
        const int tokens = length * sequences, slots = sequences + 1;
        std::vector<RadTensor> host = {
            T(nullptr, RAD_BF16, {tokens, Hg, K}), T(nullptr, RAD_BF16, {tokens, Hg, K}),
            T(nullptr, RAD_BF16, {tokens, H, V}), T(nullptr, RAD_BF16, {tokens, H, C}),
            T(nullptr, RAD_F32, {tokens, H}), T(nullptr, RAD_F32, {tokens, H}),
            T(nullptr, half ? RAD_F16 : RAD_F32, {slots, H, V, K}),
            T(nullptr, RAD_I32, {sequences + 1}), T(nullptr, RAD_BF16, {tokens, H, V}),
            T(nullptr, half ? RAD_F16 : RAD_F32, {slots, H, V, K}),
            T(nullptr, RAD_I32, {sequences}) };
        std::vector<std::vector<uint8_t>> bytes(host.size());
        std::vector<RadTensor> device = host;
        for (size_t j = 0; j < host.size(); ++j) {
            const int64_t count = host[j].shape[0] * host[j].stride[0];
            bytes[j].resize((size_t)count * esz(host[j].dtype));
            host[j].data = bytes[j].data();
            for (int64_t i = 0; i < count; ++i) {
                const float value = (float)((int)(st_mix32((uint32_t)i ^ (uint32_t)(j * 977)) % 127) - 63) / 4096;
                if (host[j].dtype == RAD_BF16) ((uint16_t*)host[j].data)[i] = h_to_bf16(value);
                else if (host[j].dtype == RAD_F16) ((uint16_t*)host[j].data)[i] = rad_f32_to_f16(value);
                else if (host[j].dtype == RAD_F32) ((float*)host[j].data)[i] = value;
            }
        }
        for (int i = 0; i <= sequences; ++i) ((int32_t*)host[7].data)[i] = i * length;
        for (int i = 0; i < sequences; ++i)
            ((int32_t*)host[10].data)[i] = sequences - i; // swapped slots; slot 0 must survive
        for (int t = 0; t < tokens; ++t) for (int h = 0; h < H; ++h) {
            const int position = (t % length) % C;
            ((float*)host[4].data)[t * H + h] = -(decay ? 8.75f : .015625f) * (position + 1);
            ((float*)host[5].data)[t * H + h] = .25f;
            for (int j = 0; j < C; ++j)
                ((uint16_t*)host[3].data)[((t * H + h) * C) + j] = h_to_bf16(
                    j == position ? 1.0f : j < position ? .000244140625f : 0.0f);
        }
        for (size_t j = 0; j < host.size(); ++j) device[j].data = tp4_copy(bytes[j].data(), bytes[j].size());
        std::vector<RadParam> params = { PI("M", tokens), PI("head_k", K), PI("head_v", V),
                                        PI("chunk", C), PF("scale", .08838834764831845) };
        RadArgs args{};
        args.t = device.data(); args.n_t = (int)device.size();
        args.p = params.data(); args.n_p = (int)params.size();
        std::vector<uint8_t> reference_o, reference_h;
        double timing[2]{};
        for (int which = 0; which < 2; ++which) {
            st_memcpy(device[8].data, bytes[8].data(), bytes[8].size(), hipMemcpyHostToDevice);
            st_memcpy(device[9].data, bytes[9].data(), bytes[9].size(), hipMemcpyHostToDevice);
            auto launch = [&]() { tp4_require(rows[which]->launch(&args, nullptr) == RAD_OK, "GDN launch refused"); };
            launch(); tp4_require(st_stream_sync(nullptr) == hipSuccess, "GDN launch failed");
            std::vector<uint8_t> out(bytes[8].size()), state(bytes[9].size());
            st_memcpy(out.data(), device[8].data, out.size(), hipMemcpyDeviceToHost);
            st_memcpy(state.data(), device[9].data, state.size(), hipMemcpyDeviceToHost);
            if (which == 0) { reference_o = out; reference_h = state; }
            tp4_require(out != bytes[8] && state != bytes[9], "GDN did not write output/state");
            for (size_t i = 0; i < out.size() / 2; ++i)
                tp4_require(std::isfinite(h_bf16(((const uint16_t*)out.data())[i])), "nonfinite GDN output");
            for (size_t i = 0; i < state.size() / esz(host[9].dtype); ++i)
                tp4_require(std::isfinite(rad_load_f32(state.data(), host[9].dtype, i)), "nonfinite GDN state");
            tp4_require(out == reference_o && state == reference_h, "GDN output or retained state differs from stock");
            const size_t slot_bytes = bytes[9].size() / slots;
            tp4_require(std::memcmp(state.data(), bytes[9].data(), slot_bytes) == 0,
                        "GDN overwrote an unowned state slot");
            tp4_warm(launch);
            timing[which] = st_time_us([&](int) { launch(); }, iters, nullptr);
            st_memcpy(out.data(), device[8].data, out.size(), hipMemcpyDeviceToHost);
            st_memcpy(state.data(), device[9].data, state.size(), hipMemcpyDeviceToHost);
            tp4_require(out == reference_o && state == reference_h, "GDN replay changed output/state");
        }
        // In-place state, as in the serving cache, across two consecutive chunks/requests.
        device[9].data = device[6].data;
        for (int which = 0; which < 2; ++which) {
            st_memcpy(device[6].data, bytes[6].data(), bytes[6].size(), hipMemcpyHostToDevice);
            for (int replay = 0; replay < 2; ++replay)
                tp4_require(rows[which]->launch(&args, nullptr) == RAD_OK, "GDN aliased launch refused");
            tp4_require(st_stream_sync(nullptr) == hipSuccess, "GDN aliased launch failed");
            std::vector<uint8_t> out(bytes[8].size()), state(bytes[6].size());
            st_memcpy(out.data(), device[8].data, out.size(), hipMemcpyDeviceToHost);
            st_memcpy(state.data(), device[6].data, state.size(), hipMemcpyDeviceToHost);
            if (!which) { reference_o = out; reference_h = state; }
            tp4_require(out == reference_o && state == reference_h, "GDN aliased replay differs from stock");
        }
        std::printf("TP4_GDN length=%d heads=%d key_heads=%d sequences=%d state=%s decay=%s stock_us=%.6f candidate_us=%.6f output=pass state_bytes=pass alias_replay=pass\n",
                    length, H, Hg, sequences, half ? "f16" : "f32", decay ? "strong" : "normal", timing[0], timing[1]);
        std::fflush(stdout);
        dfree_all();
    }
}

static int tp4_main(int argc, char** argv) {
    try {
        Plugin pl;
        tp4_require(load(&pl, argv[1]), "plugin load failed");
        if (!std::strcmp(argv[2], "--tp4-moe") && argc == 7)
            tp4_moe(pl, std::stoll(argv[3]), std::stoll(argv[4]), std::stoi(argv[5]), std::stoi(argv[6]));
        else if (!std::strcmp(argv[2], "--tp4-ar") && argc == 4) tp4_ar(pl, std::stoi(argv[3]));
        else if (!std::strcmp(argv[2], "--tp4-gdn") && argc == 5) tp4_gdn(pl, argv[3], std::stoi(argv[4]));
        else if (!std::strcmp(argv[2], "--tp4-gdn-fallback") && argc == 5) {
            tp4_gdn(pl, argv[3], std::stoi(argv[4]), 4, 2, 1);
            tp4_gdn(pl, argv[3], std::stoi(argv[4]), 12, 4, 2);
        }
        else throw std::runtime_error("usage: plugin --tp4-moe M E rank iters | --tp4-ar iters | --tp4-gdn stock_plugin iters");
        dfree_all();
        return g_fail ? 1 : 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "TP4_FAIL: %s\n", e.what());
        dfree_all();
        return 1;
    }
}
