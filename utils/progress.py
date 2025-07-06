from tqdm import tqdm
import time

def with_progress(iterable, desc="Progress", delay=0):
    bar = tqdm(iterable, desc=desc, ncols=80)
    for item in bar:
        yield item
        if delay:
            time.sleep(delay)
