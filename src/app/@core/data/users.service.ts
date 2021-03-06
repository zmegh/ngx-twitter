import { Injectable } from '@angular/core';
import { Observable } from 'rxjs/Observable';
import 'rxjs/add/observable/of';
import { of } from 'rxjs/observable/of';
import { BehaviorSubject } from 'rxjs/BehaviorSubject';
import { asObservable } from './asObservable';
import { TwitterUsersBackendService } from './twitter.user.data.service';
import { User } from '../models/twitter.user';
import * as usersData from '../../../assets/map/usersData.json';
let counter = 0;

@Injectable()
export class UserService {

  private _contacts: BehaviorSubject<Array<any>> = new BehaviorSubject(Array([]));

  private users = {
    nick: { name: 'Nick Jones', picture: 'assets/images/nick.png' },
    eva: { name: 'Eva Moor', picture: 'assets/images/eva.png' },
    jack: { name: 'Jack Williams', picture: 'assets/images/jack.png' },
    lee: { name: 'Lee Wong', picture: 'assets/images/lee.png' },
    alan: { name: 'Alan Thompson', picture: 'assets/images/alan.png' },
    kate: { name: 'Kate Martinez', picture: 'assets/images/kate.png' },
  };


  private userArray: any[];
  private twitterUser: any = {};
  private countryName: string;
  private filtered: any[] = [];

  constructor(private twitterUsersBackendService: TwitterUsersBackendService) {
    // this.userArray = Object.values(this.users);

    this.twitterUser = usersData;

  }

  get contacts() {
    return asObservable(this._contacts);
  }

  loadContacts(countryName: string) {
    let _users = [];
    this.twitterUsersBackendService.getData()
      .subscribe(
      res => {
        res = res as any[];
        res = (<any[]>res).filter(u => u.countryCode == countryName);

        res = (<any[]>res).sort(this.compare);
        res = (<any[]>res).slice(0, 10);
        let todos = (<any[]>res).map((user: any) => {

          let _user = new User(user.id, user.screen_name, user.name, user.profile_image_url_https,
            user.friends_count, user.followers_count, user.statuses_count, user.country);

          _users.push(user);
          this._contacts.next(_users);
        });
      },
      err => console.log('Error retrieving Todos')
      );
  }


  setCountryName(val: string) : void{
    this.countryName = val;
  }

  getUsers(): Observable<any> {
    return Observable.of(this.users);
  }

  getTwitterUsers(): Observable<any> {
    return Observable.of(this.twitterUser);
  }

  compare(a, b) {
    if (a.followers_count < b.followers_count)
      return 1;
    if (a.followers_count > b.followers_count)
      return -1;
    return 0;
  }

  pullTwitterUsers(val: string): any[] {
    return this.twitterUser.filter(u => u.country == val);
  }

  getUserArray(): Observable<any[]> {
    return Observable.of(this.userArray);
  }

  getUser(): Observable<any> {
    counter = (counter + 1) % this.userArray.length;
    return Observable.of(this.userArray[counter]);
  }
}
