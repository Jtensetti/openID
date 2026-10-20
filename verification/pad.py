import hashlib
from pathlib import Path
import numpy as np
import torch
from vendor.minifas.MiniFASNet import MiniFASNetV2, MiniFASNetV1SE
from vendor.minifas.generate_patches import CropImage

MODELS = [
    ('2.7_80x80_MiniFASNetV2.pth','a5eb02e1843f19b5386b953cc4c9f011c3f985d0ee2bb9819eea9a142099bec0',MiniFASNetV2,2.7),
    ('4_0_0_80x80_MiniFASNetV1SE.pth','84ee1d37d96894d5e82de5a57df044ef80a58be2b218b5ed7cdfd875ec2f5990',MiniFASNetV1SE,4.0),
]

class PresentationAttackDetector:
    def __init__(self,directory):
        self.models=[]
        torch.set_num_threads(1)
        for name,checksum,architecture,scale in MODELS:
            path=Path(directory)/name
            if hashlib.sha256(path.read_bytes()).hexdigest()!=checksum:
                raise ValueError('PAD_MODEL_INTEGRITY_FAILED')
            weights=torch.load(path,map_location='cpu',weights_only=True)
            model=architecture(conv6_kernel=(5,5))
            model.load_state_dict({key.removeprefix('module.'):value for key,value in weights.items()})
            model.eval();self.models.append((model,scale))

    def score(self,image,face):
        bbox=[int(value) for value in face[:4]]
        if min(bbox[2:])<60 or bbox[0]<0 or bbox[1]<0:
            raise ValueError('PAD_FACE_QUALITY_REJECTED')
        predictions=[]
        with torch.inference_mode():
            for model,scale in self.models:
                crop=CropImage().crop(image,bbox,scale,80,80)
                # Upstream expects BGR floats in 0..255, without normalization.
                tensor=torch.from_numpy(np.ascontiguousarray(crop.transpose(2,0,1))).float().unsqueeze(0)
                probabilities=torch.softmax(model(tensor),dim=1).numpy()[0]
                if not np.isfinite(probabilities).all():raise ValueError('INVALID_PAD_SCORE')
                predictions.append(float(probabilities[1]))
        return float(np.mean(predictions))
