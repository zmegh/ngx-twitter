import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs/Observable';
import 'rxjs/observable/of';
import 'rxjs/add/operator/share';
import 'rxjs/add/operator/map';



@Injectable()
export class TwitterUsersBackendService {

  private rawJson: string;
  private users: any[];
  private observable: Observable<any>;
  private url: string = 'assets/map/usersData.json';

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
