import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs/Observable';
import * as appConfig from '../../../appSettings.json';


@Injectable()
export class TwitterUsersBackendService {

  private rawJson: string;
  private users: any[];
  private observable: Observable<any>;
  private url = appConfig['userDataPath'];

  constructor(private http: HttpClient) {
    this.http = http;
  }

  getContactByCountryName(countryName: string) {
    return this.users.filter(u => u.country == countryName);
  }

  getData() {
       return this.http.get(this.url);
  }

}
