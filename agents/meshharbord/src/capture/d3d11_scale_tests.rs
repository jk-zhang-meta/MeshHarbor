//! Explicitly selected offscreen hardware checks. Never opens a capture item.
use super::d3d11_scale::BgraScaler;
use super::wgc_backend::{NativeReadbackForTest, test_d3d_device};
use super::{Damage, Frame, PixelFormat};
use crate::encode::resample::{Resampler, apply_target_resolution};
use crate::peer::TargetResolution;
use std::sync::Arc;
use std::time::Instant;
use windows::Win32::Graphics::Direct3D11::{
    D3D11_BIND_RENDER_TARGET, D3D11_BIND_SHADER_RESOURCE, D3D11_SUBRESOURCE_DATA,
    D3D11_TEXTURE2D_DESC, D3D11_USAGE_DEFAULT, ID3D11Device, ID3D11Texture2D,
};
use windows::Win32::Graphics::Dxgi::Common::{DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_SAMPLE_DESC};
use windows::Win32::Graphics::Dxgi::IDXGIDevice;
use windows::core::Interface;

fn pattern(width: u32, height: u32, variant: u8) -> Vec<u8> {
    let mut bytes = vec![0; width as usize * height as usize * 4];
    for y in 0..height {
        for x in 0..width {
            let color = match (x < width / 2, y < height / 2) {
                (true, true) => [24, 48, 192, 255],
                (false, true) => [192, 32, 48, 255],
                (true, false) => [32, 192, 48, 255],
                (false, false) => [160, 128, 96, 255],
            };
            let i = ((y * width + x) * 4) as usize;
            bytes[i..i + 4].copy_from_slice(&color);
            bytes[i] += variant;
        }
    }
    bytes
}

fn cost_pattern(width: u32, height: u32, variant: u8) -> Vec<u8> {
    let mut bytes = pattern(width, height, variant);
    for y in 0..height {
        for x in 0..width {
            let cx = if x < width / 2 {
                width / 4
            } else {
                width * 3 / 4
            };
            let cy = if y < height / 2 {
                height / 4
            } else {
                height * 3 / 4
            };
            if x.abs_diff(cx) <= 16 && y.abs_diff(cy) <= 16 {
                continue;
            }
            let value = x.wrapping_mul(0x9e3779b9) ^ y.wrapping_mul(0x85ebca6b);
            let at = ((y * width + x) * 4) as usize;
            bytes[at] = (value as u8).wrapping_add(variant);
            bytes[at + 1] = (value >> 8) as u8;
            bytes[at + 2] = (value >> 16) as u8;
        }
    }
    bytes
}

fn texture(device: &ID3D11Device, width: u32, height: u32, data: &[u8]) -> ID3D11Texture2D {
    let desc = D3D11_TEXTURE2D_DESC {
        Width: width,
        Height: height,
        MipLevels: 1,
        ArraySize: 1,
        Format: DXGI_FORMAT_B8G8R8A8_UNORM,
        SampleDesc: DXGI_SAMPLE_DESC {
            Count: 1,
            Quality: 0,
        },
        Usage: D3D11_USAGE_DEFAULT,
        BindFlags: (D3D11_BIND_SHADER_RESOURCE | D3D11_BIND_RENDER_TARGET).0 as u32,
        ..Default::default()
    };
    let initial = D3D11_SUBRESOURCE_DATA {
        pSysMem: data.as_ptr().cast(),
        SysMemPitch: width * 4,
        SysMemSlicePitch: 0,
    };
    let mut result = None;
    unsafe { device.CreateTexture2D(&desc, Some(&initial), Some(&mut result)) }.unwrap();
    result.unwrap()
}

fn adapter(device: &ID3D11Device) -> serde_json::Value {
    let dxgi: IDXGIDevice = device.cast().unwrap();
    let adapter = unsafe { dxgi.GetAdapter() }.unwrap();
    let desc = unsafe { adapter.GetDesc() }.unwrap();
    let end = desc
        .Description
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(desc.Description.len());
    let name = String::from_utf16_lossy(&desc.Description[..end]);
    assert!(
        !name.contains("Microsoft Basic Render"),
        "software rendering is not hardware evidence"
    );
    serde_json::json!({"name":name,"vendor_id":desc.VendorId,"device_id":desc.DeviceId,
        "dedicated_video_memory":desc.DedicatedVideoMemory,"shared_system_memory":desc.SharedSystemMemory})
}

fn frame(data: Vec<u8>, dims: (u32, u32), source: Option<(u32, u32)>) -> Arc<Frame> {
    Arc::new(Frame {
        width: dims.0,
        height: dims.1,
        stride: dims.0 * 4,
        pixel_format: PixelFormat::Bgra,
        data,
        monotonic_us: 1,
        monitor: 0,
        damage: Damage::Unknown,
        source,
    })
}

fn check_colors(data: &[u8], width: u32, height: u32, variant: u8) {
    assert_eq!(data.len(), width as usize * height as usize * 4);
    let expected = [
        [24, 48, 192, 255],
        [192, 32, 48, 255],
        [32, 192, 48, 255],
        [160, 128, 96, 255],
    ];
    for (i, (x, y)) in [
        (width / 4, height / 4),
        (width * 3 / 4, height / 4),
        (width / 4, height * 3 / 4),
        (width * 3 / 4, height * 3 / 4),
    ]
    .into_iter()
    .enumerate()
    {
        let at = ((y * width + x) * 4) as usize;
        for channel in 0..4 {
            let wanted = expected[i][channel] + if channel == 0 { variant } else { 0 };
            assert!(
                (i16::from(data[at + channel]) - i16::from(wanted)).abs() <= 4,
                "BGRA/channel/orientation mismatch at quadrant={i} channel={channel}"
            );
        }
    }
}

#[test]
#[ignore = "requires real Windows D3D11 video-processor hardware; offscreen only"]
fn offscreen_bgra_scaler_pixel_contract() {
    let (device, context) = test_d3d_device().unwrap();
    println!("X8_ADAPTER {}", adapter(&device));
    let reader = NativeReadbackForTest::new();
    for (input, output) in [
        ((64, 48), (32, 24)),
        ((192, 120), (128, 80)),
        ((130, 98), (62, 46)),
    ] {
        let pixels = pattern(input.0, input.1, 0);
        let src = texture(&device, input.0, input.1, &pixels);
        let mut scaler = BgraScaler::new(&device, &context, input, output).unwrap();
        assert!(scaler.matches(input, output));
        let scaled = scaler.read(&src).unwrap();
        check_colors(&scaled, output.0, output.1, 0);
        let unchanged = reader
            .read(&device, &context, &src, input.0, input.1)
            .unwrap();
        assert_eq!(unchanged, pixels, "scaling must not mutate source");
        let gpu_frame = frame(scaled, output, Some(input));
        assert_eq!(gpu_frame.native_dims(), input);
        let mut rs = Resampler::new();
        let same = apply_target_resolution(
            &mut rs,
            gpu_frame.clone(),
            TargetResolution::Fixed {
                width: output.0,
                height: output.1,
            },
        );
        assert!(
            Arc::ptr_eq(&same, &gpu_frame),
            "backend-scaled pixels must not scale twice"
        );
        let wrong = texture(
            &device,
            input.0 + 2,
            input.1,
            &pattern(input.0 + 2, input.1, 0),
        );
        assert!(
            scaler.read(&wrong).is_err(),
            "wrong-size input must fail, never silently crop"
        );
    }
    assert!(BgraScaler::new(&device, &context, (0, 48), (32, 24)).is_err());
    assert!(BgraScaler::new(&device, &context, (64, 48), (0, 24)).is_err());
}

fn quantile_us(samples: &[u128], percentile: usize) -> u128 {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    if percentile == 50 && sorted.len().is_multiple_of(2) {
        (sorted[sorted.len() / 2 - 1] + sorted[sorted.len() / 2]) / 2
    } else {
        sorted[(sorted.len() * percentile)
            .div_ceil(100)
            .saturating_sub(1)
            .min(sorted.len() - 1)]
    }
}

#[test]
#[ignore = "release-only explicit offscreen hardware measurement; never captures desktop"]
fn offscreen_bgra_scaler_cost() {
    if cfg!(debug_assertions) {
        panic!("CPU baseline must use an optimized release build");
    }
    let (device, context) = test_d3d_device().unwrap();
    println!("X8_ADAPTER {}", adapter(&device));
    let samples = 24;
    for (input, output) in [
        ((2400, 1600), (1200, 800)),
        ((3840, 2160), (1920, 1080)),
        ((1920, 1200), (1280, 800)),
    ] {
        let sources = [
            texture(
                &device,
                input.0,
                input.1,
                &cost_pattern(input.0, input.1, 0),
            ),
            texture(
                &device,
                input.0,
                input.1,
                &cost_pattern(input.0, input.1, 24),
            ),
        ];
        let reader = NativeReadbackForTest::new();
        let mut rs = Resampler::new();
        let cold = Instant::now();
        let mut scaler = BgraScaler::new(&device, &context, input, output).unwrap();
        let first = scaler.read(&sources[0]).unwrap();
        let cold_us = cold.elapsed().as_micros();
        check_colors(&first, output.0, output.1, 0);
        let target = TargetResolution::Fixed {
            width: output.0,
            height: output.1,
        };
        for i in 0..5 {
            let src = &sources[i % 2];
            std::hint::black_box(scaler.read(src).unwrap());
            let native = reader
                .read(&device, &context, src, input.0, input.1)
                .unwrap();
            std::hint::black_box(apply_target_resolution(
                &mut rs,
                frame(native, input, None),
                target,
            ));
        }
        let mut cpu = Vec::new();
        let mut gpu = Vec::new();
        for i in 0..samples {
            let src = &sources[i % 2];
            // Alternate operation order so neither path always gets the warmer queue.
            for gpu_first in if i % 2 == 0 {
                [true, false]
            } else {
                [false, true]
            } {
                let start = Instant::now();
                if gpu_first {
                    let data = scaler.read(src).unwrap();
                    gpu.push(start.elapsed().as_micros());
                    check_colors(&data, output.0, output.1, if i % 2 == 0 { 0 } else { 24 });
                    std::hint::black_box(data);
                } else {
                    let native = reader
                        .read(&device, &context, src, input.0, input.1)
                        .unwrap();
                    let data = apply_target_resolution(&mut rs, frame(native, input, None), target);
                    cpu.push(start.elapsed().as_micros());
                    assert_eq!((data.width, data.height), output);
                    check_colors(
                        &data.data,
                        output.0,
                        output.1,
                        if i % 2 == 0 { 0 } else { 24 },
                    );
                    std::hint::black_box(data);
                }
            }
        }
        let cpu_median = quantile_us(&cpu, 50);
        let gpu_median = quantile_us(&gpu, 50);
        println!(
            "X8_OFFSCREEN_COST {}",
            serde_json::json!({
                "input":input,"output":output,"samples":samples,"warmup_iterations":5,"profile":"release",
                "cpu":"cached native WGC readback + production Resampler",
                "gpu":"VideoProcessorBlt + CopyResource + Map + packed output",
                "cold_gpu_first_read_us":cold_us,"cpu_median_us":cpu_median,"gpu_median_us":gpu_median,
                "cpu_p95_us":quantile_us(&cpu,95),"gpu_p95_us":quantile_us(&gpu,95),
                "cpu_samples_us":cpu,"gpu_samples_us":gpu,
                "median_reduction_percent":100.0*(1.0-gpu_median as f64/cpu_median.max(1) as f64),
                "native_packed_bytes":u64::from(input.0)*u64::from(input.1)*4,
                "scaled_packed_bytes":u64::from(output.0)*u64::from(output.1)*4,
                "capture_items_opened":0,"source_textures_alternated":true,
                "source_pattern":"high-frequency RGB with solid color checkpoints",
                "scale_threads_setting":tunnel_core::env::node_env("SCALE_THREADS")
            })
        );
    }
}
