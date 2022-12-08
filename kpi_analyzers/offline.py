#!/usr/bin/python

from mobile_insight.monitor import OfflineReplayer
from kpi_analyzers.buffer_analyzer import BufferAnalyzer
import pandas as pd
import os

paths = ['./logs/',]
filename_list = [
    'board-1669149465-mobility_walking_REAL_attempt5_11_22_2022',
    'board-1669263405-mobility_driving2_11_23_2022',
    'board-1669508088-mobility_driving_desert5_11_26_2022',
    'board-1669508088-mobility_driving_desert6_11_26_2022_1',
    'board-1669508088-mobility_driving_desert6_11_26_2022_2',
    'board-1669940282-mobility_walking_ucla3_12_1_2022',
    'board-1669926487-mobility_walking_ucla1_12_1_2022',
    'board-1669928025-mobility_walking_ucla2_12_1_2022',
]


def buffer_analysis():
    for path in paths:
        for filename in filename_list:
            src = OfflineReplayer()
            src.set_input_path('{}{}.qmdl'.format(path, filename))

            analyzer = BufferAnalyzer()
            analyzer.set_source(src)

            src.run()

            os.mkdir('./{}'.format(filename))
            for metric_name, data in analyzer.rrc_split_latency_metrics.items():
                pd.DataFrame(data).to_csv('./{}/rrc_{}_{}.csv'.format(filename, filename, metric_name), index=False, header=False)

            for metric_name, data in analyzer.nas_split_latency_metrics.items():
                pd.DataFrame(data).to_csv('./{}/nas_{}_{}.csv'.format(filename, filename, metric_name), index=False, header=False)

buffer_analysis()
