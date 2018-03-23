#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

import json
import sys
from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta
import csv
import matplotlib.pyplot as plt
import matplotlib.dates as pltdate
from PIL import Image, ImageDraw, ImageFont
from pprint import pprint

DATE_FORMAT = "%d %b %y %H:%M"
FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSerif.ttf"
COLORS = [(255,200,200), (255,100,100), (190,50,50), "blue", "red", "yellow", (155, 155, 155), (150, 145, 0), (0, 23, 189), "lime"]
used_colors = {}

def draw_figure(data, output_file_name=None, width=1300, height=700, border=70, font_big=30, font_small=20, debug=False, draw_image=True):
    next_unused_color = 0
    timeline = []
    seen_locations = set()
    if debug:
        pprint(data)
    font = ImageFont.truetype (FONT, font_small)
    font_large =  ImageFont.truetype (FONT, font_big)
    total_time = int((datetime.strptime(data["last_seen"], "%d %b %y %H:%M:%S") - datetime.strptime(data["first_seen"], "%d %b %y %H:%M:%S")).total_seconds())
    print total_time
    for item in data["timeline"]:
        a = datetime.strptime(item[0], DATE_FORMAT)
        b = datetime.strptime(item[1], DATE_FORMAT)
        d = item[2]
        timeline += [[a,b,d]]

        #generate image
        W = width - (2 * border)
        H = height - (2 * border)
        W_1 = int(W * 0.85)
        H_1 = height / 2

        image = Image.new("RGB", (width, height), "white")
        min_date = timeline[0][0]
        max_date = timeline[-1][1]
        interval = max_date - min_date

        #draw frame
        draw = ImageDraw.Draw(image)
        draw.rectangle((border, border, width - border, H_1-border), fill=(128,128,128), outline=(0,0,0))

        #draw rectangles
        current_date = min_date
        date_month = min_date + relativedelta(months=1)
        current_index = 0
        prev_time = datetime(1970, 1, 1)
    for item in timeline:
        if debug:
            print item
        begin = (item[0] - min_date)
        end =  (item[1] - min_date)
        if interval.seconds != 0:
            if begin != end:
                size = (end - begin).seconds * W / (interval.seconds)
                x = begin.seconds * W / (interval.seconds) + border
            # Ignore devices seen for less than 1 minute
            else:
                continue
        else:
            # Device seen only once
            size = W
            x = begin.seconds * W + border
        if debug:
            print begin
            print end
            print size
            print x
        if item[2] not in used_colors:
            used_colors[item[2]] = COLORS[next_unused_color]
            next_unused_color += 1
        draw.rectangle((x, border + (height / 10), x + size, border + (height / 5)), fill=used_colors[item[2]], outline=(0,0,0))
        zone_name = item[2]
        seen_locations.add(item[2])
        #draw.text((x + 10, border + (height / 7)), zone_name, fill="black", font=font)
        if (item[0] - prev_time).total_seconds() > total_time / (width / 25):
            txt_height = height / 20
            txt = Image.new('RGBA', (width/15, txt_height))
            d = ImageDraw.Draw(txt)
            d.text((0, 0), str(item[0].strftime( "%H:%M")), fill="black", font=font)
            txt = txt.rotate(-45, expand=1)
            s1, s2 = txt.size
            image.paste(txt, (x - (txt_height / 2), border + (height / 5)),  txt)
            prev_time = item[0]

    #draw start and end dates
    draw.text((border, H_1 - border ), str(data["first_seen"]), fill="black", font=font) # begin
    draw.text((border + W_1, H_1 - border), str(data["last_seen"]), fill="black", font=font) # end

    # draw legend
    x = border
    size = width / 9
    draw.text((x, H_1 + (height / 25)), "legend:", fill="black", font=font_large)
    x += size
    for loc in seen_locations:
        draw.rectangle((x, H_1, x + size, H_1 + (height / 10)), fill=used_colors[loc], outline=(0,0,0))
        draw.text((x + 10, H_1 + (height / 25)), loc, fill="black", font=font)
        x += size

    delta_h = height / 20
    cur_h= H_1 + (height / 10)

    draw.text((border, cur_h), "MAC address: " + data["device_id"], fill="black", font=font_large)
    cur_h+=delta_h
    draw.text((border, cur_h), "Vendor / Manufacturer: " + data["vendor_name"], fill="black", font=font_large)
    cur_h+=delta_h
    draw.text((border, cur_h), "total number of frames: " + str(data["total_nb_frames"]), fill="black", font=font_large)
    cur_h+=delta_h
    nb_h = total_time/3600
    nb_min = total_time/60 - nb_h * 60
    draw.text((border, cur_h), "visit duration: " + str(nb_h) + "h " + str(nb_min) + "min " +str(total_time % 60) + "sec", fill="black", font=font_large)
    cur_h+=delta_h
    final_text = ""
    cur_line = "SSIDs: "
    for ssid in data["ssids"]:
        if len(cur_line + ssid) > 70:
            final_text += cur_line + "\n"
            cur_line = ""
        else:
            cur_line += ssid + ", "
    if cur_line != "":
        final_text += cur_line
    final_text = final_text[:-2] # remove final comma
    draw.text((border, cur_h), final_text, fill="black", font=font_large)

    if output_file_name is not None:
        image.save(output_file_name)
    if draw_image:
        image.show()
    return image

if __name__ == "__main__":
    data_file_name = " ".join(sys.argv[1:])
    with open(data_file_name) as data_file:
        data = json.load(data_file)
    #output_file_name = data_file_name.replace('.json','.eps')
    draw_figure(data, output_file_name)
