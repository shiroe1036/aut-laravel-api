<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use GuzzleHttp\Client;
use Laravel\Passport\Client as OClient;

class UserAuthController extends Controller
{
    public function register(Request $request){
        $data = $request->validate([
            'name' => 'required|max:255',
            'email' => 'required|email|unique:users',
            'password' => 'required|confirmed'
        ]);

        $data['password'] = bcrypt($request->password);

        $user = User::create($data);

        $token = $user->createToken('API Token')->accessToken;

        return response(['user' => $user, 'token' => $token]);
    }

    public function login(Request $request){
        $data = $request->validate([
            'email' => 'email|required',
            'password' => 'required'
        ]);

        if(!auth()->attempt($data)){
            return response([
                'error_message' => 'Incorrect Details. Please try again'
            ]);
        }

        $token = auth()->user()->createToken('API Token')->accessToken;

        return response(['user' => auth()->user(), 'token' => $token]);
    }

    public function getTokenAndRefreshToken(Request $request, OClient $oClient){
        // $data = $request->all();
        $oClient = OClient::where('password_client', 1)->first();
        return response(['user' => auth()->user(), 'token' => $token]);
        dd($request);
        $http = new Client;

        $response = $http->request('POST', 'http://localhost:8000/oauth/token', [
            'form_params' => [
                'grant_type' => 'password',
                'client_id' => $oClient->id,
                'client_secret' => $oClient->secret,
                'username' => $request->email,
                'password' => $request->password,
                'scope' => '*',
            ]
        ]);

        $result = json_decode((string) $response->getBody(), true);
        return response()->json($result, $this->successStatus);
    }
}
