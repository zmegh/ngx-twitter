import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs/Observable';
import * as appConfig from '../../../appSettings.json';

@Injectable()
export class MapDataService {

  private url = appConfig['userDataPath'];

  constructor(private http: HttpClient) {
    this.http = http;
  }

  getUserData() {
    return this.http.get(this.url);
  }

}
