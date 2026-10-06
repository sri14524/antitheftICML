import jsQR from 'jsqr';

/**
 * Decodes QR code content from a File object using HTML Canvas and jsQR.
 */
export async function decodeQrFromImageFile(file) {
  return new Promise((resolve, reject) => {
    if (!file || !file.type.startsWith('image/')) {
      return reject(new Error('Please upload a valid image file (PNG, JPG, SVG, WebP).'));
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      const img = new Image();
      img.onload = () => {
        try {
          const canvas = document.createElement('canvas');
          canvas.width = img.width;
          canvas.height = img.height;
          const ctx = canvas.getContext('2d');
          ctx.drawImage(img, 0, 0);

          const imageData = ctx.getImageData(0, 0, img.width, img.height);
          const code = jsQR(imageData.data, imageData.width, imageData.height, {
            inversionAttempts: 'attemptBoth',
          });

          if (code && code.data) {
            resolve({
              success: true,
              text: code.data.trim(),
              previewUrl: e.target.result,
            });
          } else {
            resolve({
              success: false,
              error: 'No QR pattern detected. Ensure the QR code is sharp, uncropped, and well-lit.',
              previewUrl: e.target.result,
            });
          }
        } catch (err) {
          reject(err);
        }
      };
      img.onerror = () => reject(new Error('Unable to decode image file.'));
      img.src = e.target.result;
    };
    reader.onerror = () => reject(new Error('Failed reading image file.'));
    reader.readAsDataURL(file);
  });
}
