"""
yatc_online.py
YaTC flow classifier for online inference.

Provides a single public function:
    classify_flow(pcap_path) -> (label, score)

Called exclusively by pipeline.py — not a standalone entry point.

Model: TraFormer_YaTC, nb_classes=7
Classes (alphabetical, matches ImageFolder training order):
    ["LDAP", "MSSQL", "NetBIOS", "PortMap", "SYN", "UDP", "benign"]
"""

import os
import sys
import numpy as np
import torch
import torch.backends.cudnn as cudnn
from torchvision import transforms
from PIL import Image

# ── Paths ─────────────────────────────────────────────────────────────────────
sys.path.insert(0, "/usr/ShieldGPT/classifier")

import util.misc as misc
import models_YaTC

# ── Configuration ─────────────────────────────────────────────────────────────
CHECKPOINT  = ("/usr/ShieldGPT/datasets/cic-ddos2019/output/"
               "finetune_resume/checkpoint-20.pth")
NB_CLASSES  = 7
DEVICE      = "cuda"
CLASSES     = ["LDAP", "MSSQL", "NetBIOS", "PortMap", "SYN", "UDP", "benign"]

# ── Model (loaded once at import time) ────────────────────────────────────────
_model  = None
_device = None


def _load_model():
    """Load YaTC model from checkpoint. Called once on first use."""
    global _model, _device

    _device = torch.device(DEVICE if torch.cuda.is_available() else "cpu")
    torch.manual_seed(0)
    np.random.seed(0)
    cudnn.benchmark = True

    model = models_YaTC.__dict__["TraFormer_YaTC"](
        num_classes=NB_CLASSES,
        drop_path_rate=0.1,
    )

    if not os.path.exists(CHECKPOINT):
        raise FileNotFoundError(f"YaTC checkpoint not found: {CHECKPOINT}")

    checkpoint = torch.load(CHECKPOINT, map_location="cpu")
    checkpoint_model = checkpoint["model"]
    msg = model.load_state_dict(checkpoint_model, strict=False)
    print(f"[yatc_online] Loaded checkpoint: {CHECKPOINT}")
    print(f"[yatc_online] Model state: {msg}")

    model.to(_device)
    model.half()   # FP16 for A100 efficiency
    model.eval()

    _model = model


# ── Flow image conversion ─────────────────────────────────────────────────────

def _read_flow_image(pcap_path: str) -> Image.Image | None:
    """
    Convert first 5 packets of a flow PCAP to a 40x40 grayscale image.
    IP src/dst are zeroed out to avoid address-based overfitting.
    Identical to pcap2img.py training logic.
    """
    import binascii
    from scapy.all import rdpcap

    PAD_IP = "0.0.0.0"
    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        print(f"[yatc_online] Failed to read PCAP {pcap_path}: {e}")
        return None

    data = []
    for packet in packets[:5]:
        try:
            ip = packet["IP"]
        except Exception:
            continue
        ip.src = PAD_IP
        ip.dst = PAD_IP
        header = binascii.hexlify(bytes(ip)).decode()
        try:
            payload = binascii.hexlify(bytes(packet["Raw"])).decode()
            header  = header.replace(payload, "")
        except Exception:
            payload = ""

        header  = (header  + "0" * 160)[:160]
        payload = (payload + "0" * 480)[:480]
        data.append((header, payload))

    # Pad to 5 packets if flow has fewer
    while len(data) < 5:
        data.append(("0" * 160, "0" * 480))

    final = "".join(h + p for h, p in data)
    arr   = np.array(
        [int(final[i:i+2], 16) for i in range(0, len(final), 2)],
        dtype=np.uint8
    )
    return Image.fromarray(arr.reshape(40, 40))


# ── Inference ─────────────────────────────────────────────────────────────────

@torch.no_grad()
def classify_flow(pcap_path: str) -> tuple[str, float]:
    """
    Classify a per-flow PCAP file using YaTC.

    Parameters
    ----------
    pcap_path : str
        Path to a per-flow PCAP file (max 6 packets, from splitter).

    Returns
    -------
    (label, score) : tuple[str, float]
        label : predicted class name, e.g. "SYN", "LDAP", "benign"
        score : softmax confidence in [0, 1]
    """
    global _model, _device

    # Lazy load model on first call
    if _model is None:
        _load_model()

    image = _read_flow_image(pcap_path)
    if image is None:
        return "benign", 0.0

    transform = transforms.Compose([
        transforms.Grayscale(num_output_channels=1),
        transforms.ToTensor(),
        transforms.Normalize(mean=[0.5], std=[0.5]),
    ])

    img_tensor = transform(image).reshape(1, 1, 40, 40).half()
    img_tensor = img_tensor.to(_device, non_blocking=True)

    with torch.cuda.amp.autocast():
        output = _model(img_tensor)

    probs      = torch.softmax(output.float(), dim=1)
    top_score, top_idx = probs.topk(1, dim=1)

    label = CLASSES[top_idx.item()]
    score = top_score.item()

    return label, score
