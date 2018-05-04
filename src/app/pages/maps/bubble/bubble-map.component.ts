import { Component, OnDestroy, EventEmitter, Output } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { combineLatest } from 'rxjs/observable/combineLatest';
import { takeWhile } from 'rxjs/operators/takeWhile';
import { NgxEchartsService } from 'ngx-echarts';
import { NbThemeService } from '@nebular/theme';
import { Observable } from 'rxjs/Rx';
import { ThemeSettingsComponent } from '../../../@theme/components/theme-settings/theme-settings.component';
import { ContactsComponent } from '../../../pages/dashboard/contacts/contacts.component';
import { UserService } from '../../../@core/data/users.service';

import * as latLong from 'assets/map/latLong.json';
import * as mapData from 'assets/map/mapData.json';

@Component({
  selector: 'ngx-bubble-map',
  styleUrls: ['./bubble-map.component.scss'],
  template: `
    <nb-card>
    <nb-card-header><div class='icon'></div></nb-card-header>
      <nb-card-body>
        <div echarts (chartClick)="onChartEvent($event, 'chartClick')"
                     (chartDataZoom)="onChartEvent($event, 'chartDataZoom')"
                     (onZoom)="onChartEvent($event, 'zoom')"
        [options]="options" class="echarts"></div>
      </nb-card-body>
    </nb-card>
  `,
})

export class BubbleMapComponent implements OnDestroy {

  @Output() themeChange: EventEmitter<any> = new EventEmitter();
  @Output('showUsers') showUsers: EventEmitter<any> = new EventEmitter();

  latlong: any = {};
  mapData: any = {};
  max = -Infinity;
  min = Infinity;
  options: any;

  bubbleTheme: any;
  geoColors: any[];

  private alive = true;

  constructor(private theme: NbThemeService,
              private http: HttpClient,
    private es: NgxEchartsService,
    private themeSettings: ThemeSettingsComponent,
    private contactComponent: ContactsComponent,
    private userService: UserService) {

    combineLatest([
      this.http.get('assets/map/world.json'),
      this.theme.getJsTheme()
    ])
      .pipe(takeWhile(() => this.alive))
      .subscribe(([map, config]: [any, any]) => {

        this.es.registerMap('world', map);

        this.latlong = latLong;
        this.mapData = mapData;

        const colors = config.variables;
        this.bubbleTheme = config.variables.bubbleMap;
        this.geoColors = [colors.primary, colors.info, colors.success, colors.warning, colors.danger];

        this.mapData.forEach((itemOpt) => {
          itemOpt.color = this.getRandomGeoColor();

          if (itemOpt.value > this.max) {
            this.max = itemOpt.value;
          }
          if (itemOpt.value < this.min) {
            this.min = itemOpt.value;
          }
        });

        this.options = {
          title: {
            text: 'LIVE TWEETS',
            left: 'center',
            top: 'top',
            textStyle: {
              color: this.bubbleTheme.titleColor,
            },
          },
          tooltip: {
            trigger: 'item',
            formatter: params => {
              return `${params.name}: ${params.value[2]}`;
            },
          },
          visualMap: {
            show: false,
            min: 0,
            max: this.max,
            inRange: {
              symbolSize: [6, 60],
            },
          },
          geo: {
            name: 'LIVE TWEETS',
            type: 'map',
            data: {code:
              params => {
                return params.value[3];
              }
            },
            map: 'world',
            roam: true,
            label: {
              emphasis: {
                show: false,
              },
            },
            itemStyle: {
              normal: {
                areaColor: this.bubbleTheme.areaColor,
                borderColor: this.bubbleTheme.areaBorderColor,
              },
              emphasis: {
                areaColor: this.bubbleTheme.areaHoverColor,
              },
            },
            zoom: 1.1,
          },
          series: [
            {
              type: 'scatter',
              coordinateSystem: 'geo',
              data: this.mapData.map(itemOpt => {

                if (this.latlong[itemOpt.code]) {
                  return {
                    name: itemOpt.name,
                    countryCode: itemOpt.code,
                    value: [
                      this.latlong[itemOpt.code].longitude,
                      this.latlong[itemOpt.code].latitude,
                      itemOpt.value
                    ],
                    itemStyle: {
                      normal: {
                        color: itemOpt.color,
                      },
                    },
                  };
                }
                else { }
              }),
            },
          ],
        };
      });
  }

  onChartEvent(e, m): void{
    let countryCode = '';

    if (e.componentType == "series") {
      countryCode = e.data.countryCode;
    }
    else {
      countryCode = e.event.target.eventData.name;
    }

    this.userService.loadContacts(countryCode);
    this.themeSettings.layoutSelect({ name: "Two Column", icon: "nb-layout-two-column", id: "two-column" });
  }

  onChartMouseOver(e, m): void {

  }

  refresh(): void {
    this.http.get('assets/map/mapData.json').subscribe(res => this.mapData = res as any[]);
  }

  ngOnDestroy() {
    this.alive = false;
  }

  private getRandomGeoColor() {
    const index = Math.round(Math.random() * this.geoColors.length);
    return this.geoColors[index];
  }
}
