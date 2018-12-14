import os
import abc
import logging
from copy import deepcopy
from typing import Optional
import numpy
import cv2
import OpenEXR
import Imath
from PIL import Image

logger = logging.getLogger("apps.rendering")


class OpenCVError(Exception):
    pass


class ImgRepr(object, metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def load_from_file(self, file_):
        return

    @abc.abstractmethod
    def get_pixel(self, xy):
        return

    @abc.abstractmethod
    def set_pixel(self, xy, color):
        return

    @abc.abstractmethod
    def get_size(self):
        return

    @abc.abstractmethod
    def copy(self):
        return

    @abc.abstractmethod
    def to_pil(self):
        return

    @abc.abstractmethod
    def close(self):
        return


class OpenCVImgRepr:
    def __init__(self):
        self.img = None

    def set_pixel(self, xy, color):
        xy = tuple(reversed(xy))
        bgr_color = tuple(reversed(color))
        self.img[xy] = bgr_color

    def get_pixel(self, x, y):
        # reverse because OpenCV stores colors as BGR
        return tuple(reversed(self.img[y, x]))

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        pass

    def get_height(self):
        assert self.img is not None
        return self.img.shape[0]

    def get_width(self):
        assert self.img is not None
        return self.img.shape[1]

    def resize(self, width, height, interpolation=cv2.INTER_LINEAR):
        assert self.img is not None
        self.img = cv2.resize(self.img, (width, height),
                              interpolation=interpolation)
        return self

    def load_from_file(self, path):
        try:
            self.img = cv2.imread(path, cv2.IMREAD_UNCHANGED)
            if self.img is None:
                raise OpenCVError('cv2 read image \"{}\" as None'.format(path))
        except cv2.error as e:
            logger.error('Error reading image: {}'.format(str(e)))
            raise OpenCVError('Cannot read image: {}'.format(str(e))) from e

    @staticmethod
    def empty(width, height, channels=3, dtype=numpy.uint8, color=(0, 0, 0)):
        imgRepr = OpenCVImgRepr()
        imgRepr.img = numpy.zeros((height, width, channels), dtype)
        imgRepr.img[:] = tuple(reversed(color))
        return imgRepr

    @staticmethod
    def from_image_file(image_path):
        imgRepr = OpenCVImgRepr()
        imgRepr.load_from_file(image_path)
        return imgRepr

    def get_size(self):
        return tuple(reversed(self.img.shape[:2]))

    def paste_image(self, img_repr, x, y):
        try:
            self.img[y:y + img_repr.img.shape[0], x:img_repr.img.shape[1]] = \
            img_repr.img
        except (cv2.error, ValueError) as e:
            raise OpenCVError('Pasting image failed') from e

    def add(self, other):
        try:
            self.img = cv2.add(self.img, other.img)
        except cv2.error as e:
            raise OpenCVError('opencv adding images failed') from e

    def save_with_extension(self, path, extension):
        # in PIL one can specify output name without extension
        # format was given as a second argument
        # in OpenCV extension must be given in a filename
        # some paths are without extension, need to rename it then

        file_path = '{}_{}.{}'.format(path, "tmp", extension.lower())
        self.save(file_path)
        os.replace(file_path, path)

    def save(self, path):
        try:
            cv2.imwrite(path, self.img)
        except cv2.error as e:
            logger.error('Error saving image: {}'.format(str(e)))
            raise OpenCVError('Cannot save image {}: {}'.format(path,
                                                                str(e)))

    @staticmethod
    def load_from_file_or_empty(img_path, width, height, channels=3,
                                dtype=numpy.uint8):
        imgRepr = OpenCVImgRepr()
        imgRepr.img = cv2.imread(img_path, cv2.IMREAD_UNCHANGED) or \
            OpenCVImgRepr.empty(width, height, channels, dtype)
        return imgRepr


class PILImgRepr(ImgRepr):
    def __init__(self):
        self.img = None
        self.type = "PIL"

    def load_from_file(self, file_):
        self.img = Image.open(file_)
        self.img = self.img.convert('RGB')
        self.img.name = os.path.basename(file_)

    def load_from_pil_object(self, pil_img, name="noname.png"):
        import PIL
        if not isinstance(pil_img, PIL.Image.Image):
            raise TypeError("img must be an instance of PIL.Image.Image")

        self.img = pil_img
        self.img = self.img.convert('RGB')
        self.img.name = name

    def get_name(self):
        return self.img.name

    def get_size(self):
        return self.img.size

    def get_pixel(self, xy):
        return list(self.img.getpixel(xy))

    @property
    def size(self):
        return self.get_size()

    def set_pixel(self, xy, color):
        color = tuple(int(c) for c in color)
        self.img.putpixel(xy, color)

    def copy(self):
        return deepcopy(self)

    def to_pil(self):
        return self.img

    def close(self):
        if self.img:
            self.img.close()


class EXRImgRepr(ImgRepr):
    def __init__(self):
        self.img = None
        self.type = "EXR"
        self.dw = None
        self.pt = Imath.PixelType(Imath.PixelType.FLOAT)
        self.rgb = None
        self.min = 0.0
        self.max = 1.0
        self.file_path = None

    def load_from_file(self, file_):
        self.img = OpenEXR.InputFile(file_)
        self.dw = self.img.header()['dataWindow']
        self.rgb = [Image.frombytes("F", self.get_size(),
                                    self.img.channel("RGB", self.pt))]
        self.file_path = file_
        self.name = os.path.basename(file_)

    def get_size(self):
        return self.dw.max.x - self.dw.min.x + 1, \
               self.dw.max.y - self.dw.min.y + 1

    def get_pixel(self, xy):
        return [c.getpixel(xy) for c in self.rgb]

    def set_pixel(self, xy, color):
        for c in range(0, len(self.rgb)):
            self.rgb[c].putpixel(xy, max(min(self.max, color[c]), self.min))

    def get_rgbf_extrema(self):
        extrema = [im.getextrema() for im in self.rgb]
        darkest = min([lo for (lo, hi) in extrema])
        lightest = max([hi for (lo, hi) in extrema])
        return lightest, darkest

    def to_pil(self, use_extremas=False):
        if use_extremas:
            lightest, darkest = self.get_rgbf_extrema()
        else:
            lightest = self.max
            darkest = self.min

        if lightest == darkest:
            lightest = 0.1 + darkest
        scale = 255.0 / (lightest - darkest)

        def normalize_0_255(v):
            return v * scale

        rgb8 = [im.point(normalize_0_255).convert("L") for im in self.rgb]
        return Image.merge("RGB", rgb8)

    def to_l_image(self):
        img = self.to_pil()
        return img.convert('L')

    def copy(self):
        e = EXRImgRepr()
        e.load_from_file(self.file_path)
        e.dw = deepcopy(self.dw)
        e.rgb = deepcopy(self.rgb)
        e.min = self.min
        e.max = self.max
        return e

    def close(self):
        if self.img:
            self.img.close()


def load_img(file_: str) -> Optional[ImgRepr]:
    """
    Load image from file path and return ImgRepr
    :param file_: path to the file
    :return: Return ImgRepr for special file type or None
    if there was an error
    """
    try:
        _, ext = os.path.splitext(file_)
        if ext.upper() != ".EXR":
            img = PILImgRepr()
        else:
            img = EXRImgRepr()
        img.load_from_file(file_)
        return img
    except Exception as err:
        logger.warning("Can't load img file {}:{}".format(file_, err))
        return


def load_as_PILImgRepr(file_: str) -> Optional[PILImgRepr]:
    img = load_img(file_)

    if isinstance(img, EXRImgRepr):
        img_pil = PILImgRepr()
        img_pil. \
            load_from_pil_object(img.to_pil())
        img = img_pil

    return img


def blend(img1, img2, alpha):
    (res_x, res_y) = img1.get_size()
    if img2.get_size() != (res_x, res_y):
        logger.error("Both images must have the same size.")
        return

    img = img1.copy()

    for x in range(0, res_x):
        for y in range(0, res_y):
            p1 = img1.get_pixel((x, y))
            p2 = img2.get_pixel((x, y))
            p = list(map(lambda c1, c2: c1 * (1 - alpha) + c2 * alpha, p1, p2))
            img.set_pixel((x, y), p)

    return img
