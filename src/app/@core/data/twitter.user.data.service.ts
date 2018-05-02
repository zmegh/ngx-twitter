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
  private url: string = '../../../assets/map/usersData.json';

  constructor(private http: HttpClient) {
    this.http = http;
  }

  getAllContacts() {
    return this.http.get('/todo');
  }

  getContactByCountryName(countryName: string) {
    return this.users.filter(u => u.country == countryName);
  }

  getData() {
    return this.http.get(this.url);
   /* if (this.users) {
      return Observable.of(this.users);
    } else if (this.observable) {
      // if `this.observable` is set then the request is in progress
      // return the `Observable` for the ongoing request
      return this.observable;
    } else {
      // example header (not necessary)
      let headers = new Headers();
      headers.append('Content-Type', 'application/json');
      // create the request, store the `Observable` for subsequent subscribers
      this.observable = this.http.get(this.url, {
        headers: headers
      })
        .map(response => {
          // when the cached data is available we don't need the `Observable` reference anymore
          this.observable = null;

          if (response.status == 400) {
            return "FAILURE";
          } else if (response.status == 200) {
            this.users = response.json();
            return this.users;
          }
          // make it shared so more than one subscriber can get the result
        })
        .share();
      return this.observable;*/
    }

}
