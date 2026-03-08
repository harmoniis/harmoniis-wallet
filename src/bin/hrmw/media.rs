use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use image::{codecs::jpeg::JpegEncoder, imageops::FilterType, DynamicImage, GenericImageView};

pub const MAX_UPLOAD_BYTES: usize = 1_000_000;
const MAX_POST_EDGE: u32 = 1_600;
const MAX_AVATAR_EDGE: u32 = 512;
const MIN_EDGE: u32 = 256;

pub struct PreparedImage {
    pub filename: String,
    pub content_type: String,
    pub bytes: Vec<u8>,
}

pub fn prepare_post_image(path: &Path) -> Result<PreparedImage> {
    let image = image::open(path)
        .with_context(|| format!("failed to decode image file {}", path.display()))?;
    let bytes = compress_under_limit(resize_if_needed(&image, MAX_POST_EDGE), MIN_EDGE)?;
    Ok(PreparedImage {
        filename: format!("{}.jpg", sanitize_name(path, "image")),
        content_type: "image/jpeg".to_string(),
        bytes,
    })
}

pub fn prepare_avatar_image(path: &Path) -> Result<PreparedImage> {
    let image = image::open(path)
        .with_context(|| format!("failed to decode avatar image {}", path.display()))?;
    let square = center_square(&image)?;
    let resized = square.resize_exact(MAX_AVATAR_EDGE, MAX_AVATAR_EDGE, FilterType::Lanczos3);
    let bytes = compress_under_limit(resized, MAX_AVATAR_EDGE)?;
    Ok(PreparedImage {
        filename: "avatar.jpg".to_string(),
        content_type: "image/jpeg".to_string(),
        bytes,
    })
}

fn center_square(image: &DynamicImage) -> Result<DynamicImage> {
    let (w, h) = image.dimensions();
    if w == 0 || h == 0 {
        bail!("image has invalid dimensions");
    }
    let side = w.min(h);
    let x = (w - side) / 2;
    let y = (h - side) / 2;
    Ok(image.crop_imm(x, y, side, side))
}

fn resize_if_needed(image: &DynamicImage, max_edge: u32) -> DynamicImage {
    let (w, h) = image.dimensions();
    if w <= max_edge && h <= max_edge {
        return image.clone();
    }
    image.resize(max_edge, max_edge, FilterType::Lanczos3)
}

fn compress_under_limit(mut image: DynamicImage, min_edge: u32) -> Result<Vec<u8>> {
    let qualities = [88u8, 80, 72, 65, 58, 50, 42, 35];
    for _ in 0..8 {
        for quality in qualities {
            let bytes = encode_jpeg(&image, quality)?;
            if bytes.len() <= MAX_UPLOAD_BYTES {
                return Ok(bytes);
            }
        }

        let (w, h) = image.dimensions();
        if w <= min_edge || h <= min_edge {
            break;
        }
        let next_w = ((w as f32) * 0.85).round() as u32;
        let next_h = ((h as f32) * 0.85).round() as u32;
        image = image.resize(
            next_w.max(min_edge),
            next_h.max(min_edge),
            FilterType::Lanczos3,
        );
    }
    Err(anyhow!(
        "image could not be compressed under {} bytes",
        MAX_UPLOAD_BYTES
    ))
}

fn encode_jpeg(image: &DynamicImage, quality: u8) -> Result<Vec<u8>> {
    let rgb = image.to_rgb8();
    let mut out = Vec::new();
    let mut encoder = JpegEncoder::new_with_quality(&mut out, quality);
    encoder
        .encode_image(&rgb)
        .map_err(|e| anyhow!("jpeg encode failed: {e}"))?;
    Ok(out)
}

fn sanitize_name(path: &Path, fallback: &str) -> String {
    let raw = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(fallback)
        .to_lowercase();
    let mut clean = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            clean.push(ch);
        } else if ch == '-' || ch == '_' {
            clean.push(ch);
        } else if ch.is_ascii_whitespace() {
            clean.push('-');
        }
    }
    let clean = clean.trim_matches('-').trim_matches('_').to_string();
    if clean.is_empty() {
        fallback.to_string()
    } else {
        clean
    }
}
