import { AfterViewInit, Component, OnDestroy } from '@angular/core';
import { NbThemeService } from '@nebular/theme';
import { takeWhile } from 'rxjs/operators/takeWhile';
import { InvoiceService } from '../../../@core/data/invoice.service';
import { combineLatest } from 'rxjs/observable/combineLatest';

@Component({
  selector: 'ngx-echarts-pie',
  template: `
    <div echarts [options]="options" class="echart"></div>
  `,
})
export class EchartsPieComponent implements AfterViewInit, OnDestroy {
  options: any = {};
  themeSubscription: any;
  private alive = true;

  constructor(private theme: NbThemeService, private invoiceService: InvoiceService) {
  }

  ngAfterViewInit() {
    let data = [];

    this.themeSubscription = combineLatest([
      this.invoiceService
        .echartData(),
      this.theme.getJsTheme()
    ])
      .pipe(takeWhile(() => this.alive))
      .subscribe(([chartData, config]: [any, any]) => {

        const colors = config.variables;
        const echarts: any = config.variables.echarts;
        this.options = {
          backgroundColor: echarts.bg,
          color: [colors.primaryLight, colors.dangerLight, colors.successLight, colors.warningLight],
          tooltip: {
            trigger: 'item',
            formatter: '{b} : ${c} ({d}%)',
          },
          legend: {
            orient: 'vertical',
            left: 'left',
            data: ['Overdue', 'Unpaid', 'Pending', 'Paid' ],
            textStyle: {
              color: echarts.textColor,
            },
          },
          series: [
            {
              name: 'Invoice Status',
              type: 'pie',
              radius: '80%',
              center: ['50%', '50%'],
              data: chartData,
              itemStyle: {
                emphasis: {
                  shadowBlur: 10,
                  shadowOffsetX: 0,
                  shadowColor: echarts.itemHoverShadowColor,
                },
              },
              label: {
                normal: {
                  textStyle: {
                    color: echarts.textColor,
                  },
                },
              },
              labelLine: {
                normal: {
                  lineStyle: {
                    color: echarts.axisLineColor,
                  },
                },
              },
            },
          ],
        };

      });
  }

  ngOnDestroy(): void {
    this.themeSubscription.unsubscribe();
  }
}
