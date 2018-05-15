import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs/Observable';
import * as appConfig from '../../../appSettings.json';

@Injectable()
export class MapDataService {

  private url = appConfig['mapDataPath'];

  constructor(private http: HttpClient) {
    this.http = http;
  }

  getMapData() {
    console.log('get map data');
    return this.http.get(this.url);
  }

}
